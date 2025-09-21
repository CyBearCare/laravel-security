<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use CybearCare\LaravelSecurity\Models\WafRule;

class WafEngine
{
    protected CybearApiClient $apiClient;
    protected bool $enabled;
    protected string $mode;

    public function __construct(CybearApiClient $apiClient, bool $enabled = true, string $mode = 'monitor')
    {
        $this->apiClient = $apiClient;
        $this->enabled = $enabled;
        $this->mode = $mode;
    }

    public function analyzeRequest(Request $request): array
    {
        if (!$this->enabled) {
            return [
                'action' => 'allow',
                'matched_rules' => [],
                'risk_score' => 0,
                'rules_evaluated' => 0,
            ];
        }

        $rules = $this->loadRules();
        
        // Debug logging for loaded rules
        if (config('cybear.debugging.waf_rules', false)) {
            Log::debug('WAF rules loaded', [
                'count' => count($rules),
                'path' => $request->path(),
                'rules' => $rules->map(function($rule) {
                    return [
                        'id' => $rule->rule_id,
                        'name' => $rule->name,
                        'conditions' => $rule->conditions
                    ];
                })->toArray()
            ]);
        }
        
        $analysis = [
            'action' => 'allow',
            'matched_rules' => [],
            'risk_score' => 0,
            'rules_evaluated' => count($rules),
            'processing_time' => 0,
        ];

        $startTime = microtime(true);

        foreach ($rules as $rule) {
            if ($this->evaluateRule($rule, $request)) {
                Log::info('WAF rule matched', [
                    'rule_id' => $rule->rule_id,
                    'name' => $rule->name,
                    'action' => $rule->action,
                    'path' => $request->path(),
                    'url' => $request->fullUrl()
                ]);
                
                $analysis['matched_rules'][] = [
                    'rule_id' => $rule->rule_id,
                    'name' => $rule->name,
                    'severity' => $rule->severity,
                    'category' => $rule->category,
                ];

                $analysis['risk_score'] += $this->getSeverityScore($rule->severity);

                if ($rule->action !== 'monitor') {
                    $analysis['action'] = $rule->action;
                    $analysis['rule_id'] = $rule->rule_id;
                    $analysis['action_params'] = $rule->action_params;
                    
                    $rule->increment('trigger_count');
                    $rule->update(['last_triggered' => now()]);
                    
                    break; // Stop on first blocking rule
                }
            }
        }

        $analysis['processing_time'] = (microtime(true) - $startTime) * 1000;

        // Override action based on mode
        if ($this->mode === 'monitor' && $analysis['action'] !== 'allow') {
            $analysis['original_action'] = $analysis['action'];
            $analysis['action'] = 'allow';
        }

        return $analysis;
    }

    protected function loadRules(): \Illuminate\Support\Collection
    {
        $cacheKey = 'cybear_waf_rules';
        
        if (config('cybear.waf.cache_rules', true)) {
            $rules = Cache::remember($cacheKey, config('cybear.waf.cache_ttl', 3600), function () {
                return WafRule::where('enabled', true)
                    ->orderBy('priority', 'desc')
                    ->orderBy('severity', 'desc')
                    ->get();
            });
        } else {
            $rules = WafRule::where('enabled', true)
                ->orderBy('priority', 'desc')
                ->orderBy('severity', 'desc')
                ->get();
        }

        return $rules;
    }

    protected function evaluateRule(WafRule $rule, Request $request): bool
    {
        $conditions = $rule->conditions;
        
        if (!is_array($conditions)) {
            Log::warning('WAF rule conditions not an array', [
                'rule_id' => $rule->rule_id,
                'conditions' => $conditions,
                'type' => gettype($conditions)
            ]);
            return false;
        }

        $result = $this->evaluateConditions($conditions, $request);
        
        if (config('cybear.debugging.waf_rules', false)) {
            Log::debug('WAF rule evaluation result', [
                'rule_id' => $rule->rule_id,
                'rule_name' => $rule->name,
                'result' => $result,
                'conditions' => $conditions
            ]);
        }
        
        return $result;
    }

    protected function evaluateConditions(array $conditions, Request $request): bool
    {
        $operator = $conditions['operator'] ?? 'and';
        $rules = $conditions['rules'] ?? [];

        if (empty($rules)) {
            return false;
        }

        $results = [];

        foreach ($rules as $condition) {
            $results[] = $this->evaluateCondition($condition, $request);
        }

        if ($operator === 'or') {
            return in_array(true, $results);
        }

        return !in_array(false, $results); // 'and' logic
    }

    protected function evaluateCondition(array $condition, Request $request): bool
    {
        $field = $condition['field'] ?? '';
        $operator = $condition['operator'] ?? '';
        $value = $condition['value'] ?? '';

        $requestValue = $this->getRequestValue($field, $request);

        // Debug logging for rule evaluation
        if (config('cybear.debugging.waf_rules', false)) {
            Log::debug('WAF condition evaluation', [
                'field' => $field,
                'operator' => $operator,
                'value' => $value,
                'request_value' => $requestValue,
                'path' => $request->path(),
                'url' => $request->fullUrl()
            ]);
        }

        switch ($operator) {
            case 'equals':
                return $requestValue === $value;
            case 'not_equals':
                return $requestValue !== $value;
            case 'contains':
                return str_contains($requestValue, $value);
            case 'not_contains':
                return !str_contains($requestValue, $value);
            case 'starts_with':
                return str_starts_with($requestValue, $value);
            case 'ends_with':
                return str_ends_with($requestValue, $value);
            case 'regex':
                // Validate regex pattern to prevent ReDoS attacks
                if (!$this->isValidRegex($value)) {
                    Log::warning('Invalid regex pattern in WAF rule', [
                        'pattern' => $value,
                        'field' => $field
                    ]);
                    return false;
                }
                
                // Set timeout for regex execution
                $oldTimeout = ini_get('pcre.backtrack_limit');
                ini_set('pcre.backtrack_limit', '10000');
                
                try {
                    $result = @preg_match('/' . $value . '/i', $requestValue);
                    if ($result === false) {
                        Log::warning('Regex execution failed in WAF rule', [
                            'pattern' => $value,
                            'error' => preg_last_error()
                        ]);
                        return false;
                    }
                    return $result > 0;
                } finally {
                    ini_set('pcre.backtrack_limit', $oldTimeout);
                }
            case 'ip_in_range':
                return $this->ipInRange($requestValue, $value);
            case 'length_greater':
                return strlen($requestValue) > (int)$value;
            case 'length_less':
                return strlen($requestValue) < (int)$value;
            default:
                return false;
        }
    }

    protected function getRequestValue(string $field, Request $request): string
    {
        switch ($field) {
            case 'ip':
                return $request->ip();
            case 'user_agent':
                return $request->userAgent() ?? '';
            case 'url':
                return $request->fullUrl();
            case 'path':
                return $request->path();
            case 'method':
                return $request->method();
            case 'query_string':
                return $request->getQueryString() ?? '';
            case 'post_data':
                // Sanitize sensitive data before encoding
                $data = $request->all();
                $this->sanitizeSensitiveData($data);
                return json_encode($data);
            case 'headers':
                // Remove sensitive headers before encoding
                $headers = $request->headers->all();
                unset($headers['authorization']);
                unset($headers['cookie']);
                unset($headers['x-csrf-token']);
                return json_encode($headers);
            case 'referer':
                return $request->header('referer', '');
            case 'host':
                return $request->getHost();
            default:
                // Try to get from request input
                return $request->input($field, '');
        }
    }

    protected function ipInRange(string $ip, string $range): bool
    {
        if (str_contains($range, '/')) {
            // CIDR notation
            list($subnet, $mask) = explode('/', $range);
            $mask = (int)$mask;
            
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $maskLong = ~((1 << (32 - $mask)) - 1);
            
            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        } else {
            // Single IP
            return $ip === $range;
        }
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
        // Check for common ReDoS patterns
        $dangerousPatterns = [
            '/(\w+)*/',           // Exponential backtracking
            '/(a+)+/',            // Nested quantifiers
            '/(a*)*/',            // Nested quantifiers
            '/(a|a)*/',           // Alternation with overlap
            '/(.*a){x}/',         // Catastrophic backtracking
        ];
        
        foreach ($dangerousPatterns as $dangerous) {
            if (preg_match('/\((?:[^()]+|\([^()]*\))*\)[*+]{2,}/', $pattern)) {
                return false; // Nested quantifiers detected
            }
        }
        
        // Test if pattern is valid
        return @preg_match('/' . $pattern . '/', '') !== false;
    }

    /**
     * Sanitize sensitive data from arrays
     */
    protected function sanitizeSensitiveData(array &$data): void
    {
        $sensitiveKeys = ['password', 'token', 'secret', 'api_key', 'private_key', 'credit_card'];
        
        foreach ($data as $key => &$value) {
            if (is_array($value)) {
                $this->sanitizeSensitiveData($value);
            } elseif (is_string($key)) {
                foreach ($sensitiveKeys as $sensitive) {
                    if (stripos($key, $sensitive) !== false) {
                        $data[$key] = '[REDACTED]';
                    }
                }
            }
        }
    }

    public function syncRules(): int
    {
        if (!$this->apiClient->isConfigured()) {
            Log::warning('Cannot sync WAF rules: API client not configured');
            return 0;
        }

        try {
            $response = $this->apiClient->syncRules();
            
            // Check for rules in both possible locations (data.rules or direct rules)
            $rules = $response['data']['rules'] ?? $response['rules'] ?? [];
            
            Log::debug('WAF sync response', [
                'has_data' => isset($response['data']),
                'rules_count' => count($rules),
                'response_keys' => array_keys($response)
            ]);
            
            $synced = 0;
            
            foreach ($rules as $ruleData) {
                // Ensure conditions are properly formatted
                $conditions = $ruleData['conditions'];
                if (is_string($conditions)) {
                    $conditions = json_decode($conditions, true);
                }
                
                $rule = WafRule::updateOrCreate(
                    ['rule_id' => $ruleData['rule_id']],
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
                        'source' => 'cybear',
                        'metadata' => $ruleData['metadata'] ?? null,
                    ]
                );
                
                Log::debug('WAF rule synced', [
                    'rule_id' => $rule->rule_id,
                    'name' => $rule->name,
                    'conditions' => $rule->conditions,
                    'action' => $rule->action
                ]);
                
                $synced++;
            }

            // Clear rules cache
            Cache::forget('cybear_waf_rules');
            
            Log::info('WAF rules synchronized', ['synced_count' => $synced]);
            
            return $synced;
            
        } catch (\Exception $e) {
            Log::error('Failed to sync WAF rules', ['error' => $e->getMessage()]);
            return 0;
        }
    }
}