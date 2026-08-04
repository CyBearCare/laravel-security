<?php

namespace CybearCare\LaravelSecurity\Core\Waf;

use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use CybearCare\LaravelSecurity\Core\Contract\RequestInterface;
use CybearCare\LaravelSecurity\Core\Contract\WafRuleRepositoryInterface;
use Psr\Log\LoggerInterface;

class WafEngine
{
    private const STANDARD_FIELDS = [
        'ip', 'user_agent', 'url', 'path', 'method', 'query_string',
        'post_data', 'headers', 'referer', 'host',
    ];

    private const OPERATORS = [
        'equals', 'not_equals', 'contains', 'not_contains', 'starts_with',
        'ends_with', 'regex', 'ip_in_range', 'length_greater', 'length_less',
    ];

    protected bool $enabled;

    protected string $mode;

    protected bool $inspectionTruncated = false;

    /** @var array<string, string|null> */
    protected array $requestValueCache = [];

    protected bool $rulesPrevalidated = false;

    protected int $prevalidatedInvalidRuleCount = 0;

    public function __construct(
        protected CybearApiClient $apiClient,
        protected WafRuleRepositoryInterface $ruleRepo,
        protected CacheInterface $cache,
        protected LoggerInterface $logger,
        protected CybearConfig $config
    ) {
        $this->enabled = $this->config->isWafEnabled();
        $configuredMode = $this->config->getWafMode();
        $this->mode = in_array($configuredMode, ['monitor', 'enforce'], true)
            ? $configuredMode
            : 'monitor';
    }

    public function analyzeRequest(RequestInterface $request): array
    {
        $this->inspectionTruncated = false;
        $this->requestValueCache = [];
        $this->rulesPrevalidated = false;
        $this->prevalidatedInvalidRuleCount = 0;
        $startTime = microtime(true);

        if (! $this->enabled) {
            return [
                'action' => 'allow',
                'matched_rules' => [],
                'risk_score' => 0,
                'rules_evaluated' => 0,
            ];
        }

        $loadedRules = $this->loadRules();
        $maximumRules = max(1, min(5000, $this->config->getWafMaxRules()));
        $rules = array_slice($loadedRules, 0, $maximumRules);

        // Debug logging for loaded rules
        if ($this->config->isWafDebugEnabled()) {
            $this->logger->debug('WAF rules loaded', [
                'count' => count($rules),
                'request_id' => $request->getRequestId(),
                'rules_truncated' => count($loadedRules) > count($rules),
            ]);
        }

        $analysis = [
            'action' => 'allow',
            'matched_rules' => [],
            'risk_score' => 0,
            'rules_evaluated' => 0,
            'invalid_rule_count' => $this->prevalidatedInvalidRuleCount,
            'expired_rule_count' => 0,
            'out_of_scope_rule_count' => 0,
            'rollout_skipped_rule_count' => 0,
            'rules_truncated' => count($loadedRules) > count($rules),
            'inspection_truncated' => false,
            'processing_time' => 0,
        ];

        foreach ($rules as $rule) {
            if (! $this->rulesPrevalidated && ! $this->isValidRuntimeRule($rule)) {
                $analysis['invalid_rule_count']++;
                $this->logger->warning('Skipped an invalid local WAF rule', [
                    'rule_id' => is_array($rule) ? ($rule['rule_id'] ?? null) : null,
                ]);

                continue;
            }

            $hasLifecycleConstraint = ! empty($rule['expires_at'])
                || ! empty($rule['scope'])
                || (int) ($rule['rollout_percentage'] ?? 100) < 100;
            $applicability = $hasLifecycleConstraint
                ? $this->ruleApplicability($rule, $request)
                : null;
            if ($applicability !== null) {
                $analysis[$applicability.'_rule_count']++;

                continue;
            }

            $analysis['rules_evaluated']++;
            try {
                $matched = $this->evaluateRule($rule, $request);
            } catch (\Throwable $exception) {
                $analysis['invalid_rule_count']++;
                $this->logger->warning('WAF rule evaluation failed and the rule was skipped', [
                    'rule_id' => $rule['rule_id'],
                    'error_type' => $exception::class,
                ]);

                continue;
            }

            if (! $matched) {
                continue;
            }

            $this->logger->info('WAF rule matched', [
                'rule_id' => $rule['rule_id'],
                'action' => $rule['action'],
                'request_id' => $request->getRequestId(),
            ]);

            $analysis['matched_rules'][] = [
                'rule_id' => $rule['rule_id'],
                'name' => $rule['name'],
                'severity' => $rule['severity'],
                'category' => $rule['category'],
                'version' => (int) ($rule['version'] ?? 1),
                'finding_id' => $rule['finding_id'] ?? null,
                'rollout_percentage' => (int) ($rule['rollout_percentage'] ?? 100),
            ];

            $analysis['risk_score'] = min(
                100,
                $analysis['risk_score'] + $this->getSeverityScore($rule['severity']),
            );

            try {
                $this->ruleRepo->incrementTriggerCount($rule['rule_id']);
                $this->ruleRepo->updateLastTriggered($rule['rule_id'], new \DateTimeImmutable);
            } catch (\Throwable $exception) {
                $this->logger->warning('Failed to update WAF rule trigger telemetry', [
                    'rule_id' => $rule['rule_id'],
                    'error_type' => $exception::class,
                ]);
            }

            if ($rule['action'] !== 'monitor') {
                $analysis['action'] = $rule['action'];
                $analysis['rule_id'] = $rule['rule_id'];
                $analysis['block_reason'] = 'A web application firewall rule matched.';
                if (is_array($rule['action_params'] ?? null)) {
                    $analysis['action_params'] = $rule['action_params'];
                }

                break;
            }
        }

        $analysis['processing_time'] = (microtime(true) - $startTime) * 1000;
        $analysis['inspection_truncated'] = $this->inspectionTruncated;

        // Override action based on mode
        if ($this->mode === 'monitor' && $analysis['action'] !== 'allow') {
            $analysis['original_action'] = $analysis['action'];
            $analysis['action'] = 'allow';
        }

        return $analysis;
    }

    protected function loadRules(): array
    {
        $cacheKey = 'cybear_waf_rules';

        if ($this->config->isWafCacheRulesEnabled()) {
            $bundle = $this->cache->remember(
                $cacheKey,
                $this->config->getWafCacheTtl(),
                fn (): array => $this->validatedRuleBundle(),
            );

            if (is_array($bundle)
                && ($bundle['schema_version'] ?? null) === 2
                && is_array($bundle['rules'] ?? null)
                && is_int($bundle['invalid_rule_count'] ?? null)
                && $this->isStructurallyValidCachedRules($bundle['rules'])) {
                $this->rulesPrevalidated = true;
                $this->prevalidatedInvalidRuleCount = max(0, $bundle['invalid_rule_count']);

                return $bundle['rules'];
            }

            $this->cache->forget($cacheKey);
            $bundle = $this->cache->remember(
                $cacheKey,
                $this->config->getWafCacheTtl(),
                fn (): array => $this->validatedRuleBundle(),
            );
            $this->rulesPrevalidated = true;
            $this->prevalidatedInvalidRuleCount = $bundle['invalid_rule_count'];

            return $bundle['rules'];
        }

        return $this->ruleRepo->findEnabledOrderedByPriority();
    }

    /**
     * @return array{
     *     schema_version: int,
     *     rules: list<array>,
     *     invalid_rule_count: int
     * }
     */
    protected function validatedRuleBundle(): array
    {
        $valid = [];
        $invalidCount = 0;

        foreach ($this->ruleRepo->findEnabledOrderedByPriority() as $rule) {
            if (! $this->isValidRuntimeRule($rule)) {
                $invalidCount++;
                $this->logger->warning('Skipped an invalid local WAF rule', [
                    'rule_id' => is_array($rule) ? ($rule['rule_id'] ?? null) : null,
                ]);

                continue;
            }

            $valid[] = $rule;
        }

        return [
            'schema_version' => 2,
            'rules' => $valid,
            'invalid_rule_count' => $invalidCount,
        ];
    }

    protected function isStructurallyValidCachedRules(array $rules): bool
    {
        foreach ($rules as $rule) {
            if (! is_array($rule)
                || ! is_string($rule['rule_id'] ?? null)
                || ! is_string($rule['name'] ?? null)
                || ! is_string($rule['category'] ?? null)
                || ! is_string($rule['severity'] ?? null)
                || ! is_string($rule['action'] ?? null)
                || ! is_array($rule['conditions'] ?? null)) {
                return false;
            }
        }

        return true;
    }

    protected function evaluateRule(array $rule, RequestInterface $request): bool
    {
        $conditions = $rule['conditions'];

        if (! is_array($conditions)) {
            $this->logger->warning('WAF rule conditions not an array', [
                'rule_id' => $rule['rule_id'],
                'conditions' => $conditions,
                'type' => gettype($conditions),
            ]);

            return false;
        }

        $result = $this->evaluateConditions($conditions, $request);

        if ($this->config->isWafDebugEnabled()) {
            $this->logger->debug('WAF rule evaluation result', [
                'rule_id' => $rule['rule_id'],
                'result' => $result,
                'condition_count' => count($conditions['rules'] ?? []),
            ]);
        }

        return $result;
    }

    protected function evaluateConditions(array $conditions, RequestInterface $request): bool
    {
        $operator = $conditions['operator'];

        foreach ($conditions['rules'] as $condition) {
            $matched = $this->evaluateCondition($condition, $request);
            if ($operator === 'or' && $matched) {
                return true;
            }
            if ($operator === 'and' && ! $matched) {
                return false;
            }
        }

        return $operator === 'and';
    }

    protected function evaluateCondition(array $condition, RequestInterface $request): bool
    {
        $field = $condition['field'];
        $operator = $condition['operator'];
        $value = (string) $condition['value'];

        $requestValue = $this->getRequestValue($field, $request);
        if ($requestValue === null) {
            return false;
        }

        // Debug logging for rule evaluation
        if ($this->config->isWafDebugEnabled()) {
            $this->logger->debug('WAF condition evaluation', [
                'field' => $field,
                'operator' => $operator,
                'rule_value_bytes' => strlen($value),
                'request_value_bytes' => strlen($requestValue),
            ]);
        }

        if ($operator !== 'regex') {
            $value = $this->normalizeComparisonValue($field, $value);
        }

        if ($value === ''
            && in_array($operator, ['contains', 'not_contains', 'starts_with', 'ends_with', 'regex', 'ip_in_range'], true)) {
            return false;
        }

        switch ($operator) {
            case 'equals':
                return $requestValue === $value;
            case 'not_equals':
                return $requestValue !== $value;
            case 'contains':
                return str_contains($requestValue, $value);
            case 'not_contains':
                return ! str_contains($requestValue, $value);
            case 'starts_with':
                return str_starts_with($requestValue, $value);
            case 'ends_with':
                return str_ends_with($requestValue, $value);
            case 'regex':
                // Validate regex pattern to prevent ReDoS attacks
                if (! $this->isValidRegex($value)) {
                    $this->logger->warning('Invalid regex pattern in WAF rule', [
                        'pattern' => $value,
                        'field' => $field,
                    ]);

                    return false;
                }

                $result = @preg_match($this->compileRegex($value), $requestValue);
                if ($result === false) {
                    $this->logger->warning('Regex execution failed in WAF rule', [
                        'pattern_hash' => hash('sha256', $value),
                        'error' => preg_last_error(),
                    ]);

                    return false;
                }

                return $result > 0;
            case 'ip_in_range':
                return $this->ipInRange($requestValue, $value);
            case 'length_greater':
                return strlen($requestValue) > (int) $value;
            case 'length_less':
                return strlen($requestValue) < (int) $value;
            default:
                return false;
        }
    }

    protected function getRequestValue(string $field, RequestInterface $request): ?string
    {
        if (array_key_exists($field, $this->requestValueCache)) {
            return $this->requestValueCache[$field];
        }

        $value = match ($field) {
            'ip' => $request->getIp(),
            'user_agent' => $request->getUserAgent() ?? '',
            'url' => $request->getFullUrl(),
            'path' => $request->getPath(),
            'method' => strtoupper($request->getMethod()),
            'query_string' => $request->getQueryString() ?? '',
            'post_data' => $this->inspectionJson($request->getAllInput()),
            'headers' => $this->inspectionJson(array_change_key_case($request->getHeaders(), CASE_LOWER)),
            'referer' => $request->getHeader('referer', ''),
            'host' => strtolower($request->getHost()),
            default => $this->inputFieldValue($request, $field),
        };

        return $this->requestValueCache[$field] = $value === null
            ? null
            : $this->normalizeComparisonValue($field, $this->bounded($value));
    }

    protected function ipInRange(string $ip, string $range): bool
    {
        if (! str_contains($range, '/')) {
            return hash_equals($range, $ip);
        }

        [$subnet, $prefix] = array_pad(explode('/', $range, 2), 2, null);
        if ($prefix === null || ! ctype_digit($prefix)) {
            return false;
        }

        $addressBytes = @inet_pton($ip);
        $subnetBytes = @inet_pton($subnet);
        if ($addressBytes === false || $subnetBytes === false || strlen($addressBytes) !== strlen($subnetBytes)) {
            return false;
        }

        $bits = strlen($addressBytes) * 8;
        $prefixLength = (int) $prefix;
        if ($prefixLength < 0 || $prefixLength > $bits) {
            return false;
        }

        $wholeBytes = intdiv($prefixLength, 8);
        $remainingBits = $prefixLength % 8;

        if (substr($addressBytes, 0, $wholeBytes) !== substr($subnetBytes, 0, $wholeBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;

        return (ord($addressBytes[$wholeBytes]) & $mask) === (ord($subnetBytes[$wholeBytes]) & $mask);
    }

    protected function getSeverityScore(string $severity): int
    {
        switch ($severity) {
            case 'low':
                return 1;
            case 'medium':
                return 3;
            case 'high':
                return 7;
            case 'critical':
                return 10;
            default:
                return 1;
        }
    }

    /**
     * Validate regex pattern to prevent ReDoS attacks
     */
    protected function isValidRegex(string $pattern): bool
    {
        if ($pattern === '' || strlen($pattern) > 2048) {
            return false;
        }

        if (preg_match('/\((?:[^()\\\\]|\\\\.)*[+*](?:[^()\\\\]|\\\\.)*\)[+*{]/', $pattern)) {
            return false;
        }

        return @preg_match($this->compileRegex($pattern), '') !== false;
    }

    protected function compileRegex(string $pattern): string
    {
        return '~(*LIMIT_MATCH=10000)(*LIMIT_RECURSION=1000)'
            .str_replace('~', '\\~', $pattern)
            .'~iD';
    }

    protected function isValidField(string $field): bool
    {
        return in_array($field, self::STANDARD_FIELDS, true)
            || preg_match('/^[A-Za-z0-9_.-]{1,128}$/', $field) === 1;
    }

    protected function normalizeComparisonValue(string $field, string $value): string
    {
        $value = str_replace("\0", '', $value);

        if (in_array($field, ['url', 'path', 'query_string', 'post_data', 'referer'], true)) {
            for ($depth = 0; $depth < 3; $depth++) {
                $decoded = rawurldecode($value);
                if ($decoded === $value) {
                    break;
                }
                $value = $decoded;
            }
            $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        if ($field === 'path') {
            $value = '/'.ltrim(str_replace('\\', '/', $value), '/');
        } elseif ($field === 'method') {
            $value = strtoupper($value);
        } elseif ($field === 'host') {
            $value = strtolower($value);
        }

        return $this->bounded($value);
    }

    protected function inputFieldValue(RequestInterface $request, string $field): ?string
    {
        $missing = new \stdClass;
        $value = $request->getInput($field, $missing);
        if ($value === $missing) {
            return null;
        }

        if (is_string($value) || is_numeric($value) || is_bool($value)) {
            return (string) $value;
        }

        return is_array($value) ? $this->inspectionJson($value) : null;
    }

    protected function inspectionJson(array $value): string
    {
        $count = 0;
        $normalized = $this->normalizeInspectionValue($value, 0, $count);

        return (string) json_encode(
            $normalized,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );
    }

    protected function normalizeInspectionValue(mixed $value, int $depth, int &$count): mixed
    {
        if ($depth >= 6 || $count >= 500) {
            $this->inspectionTruncated = true;

            return '[TRUNCATED]';
        }

        if (is_array($value)) {
            $normalized = [];
            foreach ($value as $key => $item) {
                if (++$count > 500) {
                    $this->inspectionTruncated = true;
                    $normalized['_truncated'] = true;
                    break;
                }
                $normalized[is_string($key) ? substr($key, 0, 200) : $key] =
                    $this->normalizeInspectionValue($item, $depth + 1, $count);
            }

            return $normalized;
        }

        if (is_string($value)) {
            return $this->bounded($value);
        }

        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        return '[NON_SCALAR]';
    }

    protected function bounded(string $value): string
    {
        $maximum = max(
            1024,
            min(1024 * 1024, $this->config->getWafMaxInspectionBytes()),
        );
        if (strlen($value) <= $maximum) {
            return $value;
        }

        $this->inspectionTruncated = true;

        return substr($value, 0, $maximum);
    }

    protected function isValidRuntimeRule(mixed $rule): bool
    {
        if (! is_array($rule)) {
            return false;
        }

        foreach (['rule_id', 'name', 'category', 'severity', 'conditions', 'action'] as $required) {
            if (! array_key_exists($required, $rule)) {
                return false;
            }
        }

        return is_string($rule['rule_id'])
            && $rule['rule_id'] !== ''
            && strlen($rule['rule_id']) <= 100
            && is_string($rule['name'])
            && strlen($rule['name']) <= 200
            && is_string($rule['category'])
            && strlen($rule['category']) <= 100
            && in_array($rule['severity'], ['low', 'medium', 'high', 'critical'], true)
            && is_array($rule['conditions'])
            && $this->isValidConditionGroup($rule['conditions'])
            && in_array($rule['action'], ['block', 'monitor', 'challenge', 'redirect'], true)
            && (! isset($rule['action_params']) || is_array($rule['action_params']))
            && $this->isValidLifecycle($rule);
    }

    public function syncRules(): int
    {
        if (! $this->apiClient->isConfigured()) {
            throw new \RuntimeException('Cannot sync WAF rules: API client is not configured.');
        }

        try {
            $response = $this->apiClient->syncRules();
            if (($response['success'] ?? true) === false) {
                throw new \RuntimeException(
                    (string) ($response['message'] ?? 'Cybear rejected the WAF rule sync request.'),
                );
            }

            $responseData = is_array($response['data'] ?? null) ? $response['data'] : [];
            $hasAuthoritativeRules = array_key_exists('rules', $responseData)
                || array_key_exists('rules', $response);
            $rules = $responseData['rules'] ?? $response['rules'] ?? [];

            if (! is_array($rules)) {
                throw new \UnexpectedValueException('Cybear WAF sync returned an invalid rules payload.');
            }

            $this->logger->debug('WAF sync response', [
                'has_data' => isset($response['data']),
                'rules_count' => count($rules),
                'response_keys' => array_keys($response),
            ]);

            $synced = 0;
            $syncedRuleIds = [];
            $invalidRules = false;

            foreach ($rules as $ruleData) {
                if (is_array($ruleData) && is_string($ruleData['conditions'] ?? null)) {
                    $ruleData['conditions'] = json_decode($ruleData['conditions'], true);
                }

                if (! $this->isValidSyncedRule($ruleData)) {
                    $invalidRules = true;
                    $this->logger->warning('Skipped an invalid WAF rule from the sync response', [
                        'rule_id' => is_array($ruleData) ? ($ruleData['rule_id'] ?? null) : null,
                    ]);

                    continue;
                }

                $conditions = $ruleData['conditions'];
                $existing = $this->ruleRepo->findByRuleId($ruleData['rule_id']);
                if (is_array($existing)
                    && ($existing['source'] ?? null) !== 'cybear') {
                    $invalidRules = true;
                    $this->logger->warning('Skipped a Cybear WAF rule that conflicts with a local rule ID', [
                        'rule_id' => $ruleData['rule_id'],
                    ]);

                    continue;
                }

                $incomingVersion = (int) ($ruleData['version'] ?? 1);
                if (is_array($existing)
                    && (int) ($existing['version'] ?? 1) > $incomingVersion) {
                    $syncedRuleIds[] = $ruleData['rule_id'];
                    $this->logger->warning('Skipped a stale WAF rule version from sync', [
                        'rule_id' => $ruleData['rule_id'],
                        'incoming_version' => $incomingVersion,
                        'stored_version' => (int) ($existing['version'] ?? 1),
                    ]);

                    continue;
                }

                $this->ruleRepo->updateOrCreateByRuleId(
                    $ruleData['rule_id'],
                    [
                        'name' => $ruleData['name'],
                        'description' => $ruleData['description'] ?? null,
                        'category' => $ruleData['category'],
                        'severity' => $ruleData['severity'],
                        'conditions' => $conditions,
                        'action' => $ruleData['action'],
                        'action_params' => $ruleData['action_params'] ?? null,
                        'enabled' => $ruleData['enabled'] ?? true,
                        'priority' => $ruleData['priority'] ?? 100,
                        'version' => $incomingVersion,
                        'scope' => $ruleData['scope'] ?? null,
                        'rollout_percentage' => $ruleData['rollout_percentage'] ?? 100,
                        'expires_at' => $ruleData['expires_at'] ?? null,
                        'finding_id' => $ruleData['finding_id'] ?? null,
                        'owner' => $ruleData['owner'] ?? null,
                        'reason' => $ruleData['reason'] ?? null,
                        'source' => 'cybear',
                        'metadata' => $ruleData['metadata'] ?? null,
                    ]
                );

                $this->logger->debug('WAF rule synced', [
                    'rule_id' => $ruleData['rule_id'],
                    'name' => $ruleData['name'],
                    'action' => $ruleData['action'],
                ]);

                $synced++;
                $syncedRuleIds[] = $ruleData['rule_id'];
            }

            if ($hasAuthoritativeRules && ! $invalidRules) {
                $deleted = $this->ruleRepo->deleteBySourceExcludingIds('cybear', $syncedRuleIds);

                if ($deleted > 0) {
                    $this->logger->info('WAF rules removed (deleted on SaaS)', ['deleted_count' => $deleted]);
                }
            }

            $this->cache->forget('cybear_waf_rules');
            if (! $invalidRules) {
                $cursor = $responseData['cursor']
                    ?? $responseData['synced_at']
                    ?? $response['cursor']
                    ?? $response['synced_at']
                    ?? (new \DateTimeImmutable)->format(\DateTimeInterface::ATOM);
                $this->cache->put('cybear_rules_last_sync', (string) $cursor, 86400);
            }

            $this->logger->info('WAF rules synchronized', ['synced_count' => $synced]);

            return $synced;

        } catch (\Throwable $e) {
            $this->logger->error('Failed to sync WAF rules', ['error_type' => $e::class]);
            throw $e;
        }
    }

    protected function isValidSyncedRule(mixed $rule): bool
    {
        if (! is_array($rule)) {
            return false;
        }

        foreach (['rule_id', 'name', 'category', 'severity', 'conditions', 'action'] as $required) {
            if (! array_key_exists($required, $rule)) {
                return false;
            }
        }

        return is_string($rule['rule_id'])
            && $rule['rule_id'] !== ''
            && strlen($rule['rule_id']) <= 100
            && is_string($rule['name'])
            && $rule['name'] !== ''
            && strlen($rule['name']) <= 200
            && is_string($rule['category'])
            && $rule['category'] !== ''
            && strlen($rule['category']) <= 100
            && in_array($rule['severity'], ['low', 'medium', 'high', 'critical'], true)
            && in_array($rule['action'], ['block', 'monitor', 'challenge', 'redirect'], true)
            && is_array($rule['conditions'])
            && $this->isValidConditionGroup($rule['conditions'])
            && (! isset($rule['action_params']) || is_array($rule['action_params']))
            && (! isset($rule['enabled']) || is_bool($rule['enabled']))
            && (! isset($rule['priority'])
                || (is_int($rule['priority']) && $rule['priority'] >= 0 && $rule['priority'] <= 100000))
            && $this->isValidLifecycle($rule);
    }

    protected function ruleApplicability(array $rule, RequestInterface $request): ?string
    {
        if ($this->isExpired($rule['expires_at'] ?? null)) {
            return 'expired';
        }

        $scope = $rule['scope'] ?? null;
        if (is_array($scope) && $scope !== [] && ! $this->scopeMatches($scope, $request)) {
            return 'out_of_scope';
        }

        $rollout = (int) ($rule['rollout_percentage'] ?? 100);
        if ($rollout <= 0) {
            return 'rollout_skipped';
        }

        if ($rollout < 100) {
            $digest = hash_hmac(
                'sha256',
                $rule['rule_id']."\n".$request->getIp(),
                (string) $this->config->getAppKey(),
                true,
            );
            $bucket = (unpack('N', substr($digest, 0, 4))[1] % 100) + 1;
            if ($bucket > $rollout) {
                return 'rollout_skipped';
            }
        }

        return null;
    }

    protected function scopeMatches(array $scope, RequestInterface $request): bool
    {
        $values = [
            'methods' => strtoupper($request->getMethod()),
            'hosts' => strtolower($request->getHost()),
            'route_names' => $request->getRouteName(),
            'route_uris' => $request->getRouteUri(),
        ];

        foreach ($values as $key => $actual) {
            if (! isset($scope[$key])) {
                continue;
            }

            if ($actual === null || ! in_array($actual, $scope[$key], true)) {
                return false;
            }
        }

        return true;
    }

    protected function isExpired(mixed $expiresAt): bool
    {
        if ($expiresAt === null || $expiresAt === '') {
            return false;
        }

        try {
            $expiry = $expiresAt instanceof \DateTimeInterface
                ? $expiresAt
                : new \DateTimeImmutable((string) $expiresAt);
        } catch (\Throwable) {
            return true;
        }

        return $expiry->getTimestamp() <= time();
    }

    protected function isValidLifecycle(array $rule): bool
    {
        if (isset($rule['version'])
            && (! is_int($rule['version']) || $rule['version'] < 1 || $rule['version'] > 2147483647)) {
            return false;
        }

        if (isset($rule['rollout_percentage'])
            && (! is_int($rule['rollout_percentage'])
                || $rule['rollout_percentage'] < 0
                || $rule['rollout_percentage'] > 100)) {
            return false;
        }

        if (isset($rule['scope'])
            && $rule['scope'] !== null
            && (! is_array($rule['scope']) || ! $this->isValidScope($rule['scope']))) {
            return false;
        }

        if (isset($rule['expires_at'])
            && $rule['expires_at'] !== null
            && ! $rule['expires_at'] instanceof \DateTimeInterface
            && (! is_string($rule['expires_at'])
                || strlen($rule['expires_at']) > 40
                || ! $this->isValidDate($rule['expires_at']))) {
            return false;
        }

        foreach (['finding_id' => 100, 'owner' => 200, 'reason' => 2000] as $key => $maximum) {
            if (isset($rule[$key])
                && $rule[$key] !== null
                && (! is_string($rule[$key]) || strlen($rule[$key]) > $maximum)) {
                return false;
            }
        }

        return true;
    }

    protected function isValidScope(array $scope): bool
    {
        if (array_diff(array_keys($scope), ['methods', 'hosts', 'route_names', 'route_uris']) !== []) {
            return false;
        }

        foreach ($scope as $key => $values) {
            if (! is_array($values) || $values === [] || count($values) > 50) {
                return false;
            }

            foreach ($values as $value) {
                if (! is_string($value) || $value === '' || strlen($value) > 500) {
                    return false;
                }
                if ($key === 'methods' && preg_match('/^[A-Z]{3,10}$/', $value) !== 1) {
                    return false;
                }
                if ($key === 'hosts' && strtolower($value) !== $value) {
                    return false;
                }
            }
        }

        return true;
    }

    protected function isValidDate(string $value): bool
    {
        try {
            new \DateTimeImmutable($value);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    protected function isValidConditionGroup(array $conditions): bool
    {
        $operator = $conditions['operator'] ?? null;
        $rules = $conditions['rules'] ?? null;
        $maximum = max(1, min(500, $this->config->getWafMaxConditionsPerRule()));

        if (! in_array($operator, ['and', 'or'], true)
            || ! is_array($rules)
            || $rules === []
            || count($rules) > $maximum) {
            return false;
        }

        foreach ($rules as $condition) {
            if (! is_array($condition)
                || ! is_string($condition['field'] ?? null)
                || ! $this->isValidField($condition['field'])
                || ! is_string($condition['operator'] ?? null)
                || ! in_array($condition['operator'], self::OPERATORS, true)
                || ! array_key_exists('value', $condition)
                || ! is_scalar($condition['value'])
                || ! $this->isValidConditionValue(
                    $condition['operator'],
                    $condition['value'],
                )) {
                return false;
            }
        }

        return true;
    }

    protected function isValidConditionValue(string $operator, mixed $value): bool
    {
        $value = (string) $value;
        $maximumBytes = max(
            1024,
            min(1024 * 1024, $this->config->getWafMaxInspectionBytes()),
        );

        if (strlen($value) > $maximumBytes) {
            return false;
        }

        if (in_array(
            $operator,
            ['contains', 'not_contains', 'starts_with', 'ends_with'],
            true,
        )) {
            return $value !== '';
        }

        if (in_array($operator, ['length_greater', 'length_less'], true)) {
            return preg_match('/^(0|[1-9][0-9]{0,6})$/', $value) === 1
                && (int) $value <= $maximumBytes;
        }

        if ($operator === 'regex') {
            return $this->isValidRegex($value);
        }

        if ($operator === 'ip_in_range') {
            return $this->isValidIpRange($value);
        }

        return true;
    }

    protected function isValidIpRange(string $range): bool
    {
        if (! str_contains($range, '/')) {
            return filter_var($range, FILTER_VALIDATE_IP) !== false;
        }

        [$network, $prefix] = array_pad(explode('/', $range, 2), 2, null);
        if ($prefix === null
            || ! ctype_digit($prefix)
            || filter_var($network, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $networkBytes = @inet_pton($network);
        if ($networkBytes === false) {
            return false;
        }

        return (int) $prefix <= strlen($networkBytes) * 8;
    }
}
