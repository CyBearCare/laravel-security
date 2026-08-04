<?php

namespace CybearCare\LaravelSecurity\Core\Audit;

use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\AuditLogRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\BlockedRequestRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Contract\RequestInterface;
use CybearCare\LaravelSecurity\Core\Contract\WafRuleRepositoryInterface;
use CybearCare\LaravelSecurity\Core\Sanitizer\DataSanitizer;
use Psr\Log\LoggerInterface;

class AuditLogger
{
    protected AuditLogRepositoryInterface $auditLogRepo;

    protected BlockedRequestRepositoryInterface $blockedRequestRepo;

    protected WafRuleRepositoryInterface $wafRuleRepo;

    protected LoggerInterface $logger;

    protected CybearConfig $config;

    public function __construct(
        AuditLogRepositoryInterface $auditLogRepo,
        BlockedRequestRepositoryInterface $blockedRequestRepo,
        WafRuleRepositoryInterface $wafRuleRepo,
        LoggerInterface $logger,
        CybearConfig $config,
    ) {
        $this->auditLogRepo = $auditLogRepo;
        $this->blockedRequestRepo = $blockedRequestRepo;
        $this->wafRuleRepo = $wafRuleRepo;
        $this->logger = $logger;
        $this->config = $config;
    }

    public function logRequest(
        RequestInterface $request,
        int $responseCode,
        float $processingTime,
        ?string $userId = null,
        ?string $sessionId = null,
    ): void {
        if (! $this->config->isAuditEnabled() || ! $this->config->isAuditLogRequestsEnabled()) {
            return;
        }

        try {
            $logData = [
                'app_id' => $this->config->getAppId() ?? $this->config->getAppName(),
                'event_type' => 'http_request',
                'user_id' => $userId,
                'session_id' => DataSanitizer::hashSessionId($sessionId, $this->config->getAppKey()),
                'ip_address' => $request->getIp(),
                'user_agent' => DataSanitizer::sanitizeText($request->getUserAgent(), 1000),
                'url' => DataSanitizer::sanitizeUrl(
                    $request->getFullUrl(),
                    (bool) config('cybear.audit.capture_query_values', false),
                ),
                'method' => substr($request->getMethod(), 0, 10),
                'headers' => config('cybear.audit.capture_headers', false)
                    ? DataSanitizer::sanitizeHeaders($request->getHeaders())
                    : null,
                'payload' => config('cybear.audit.capture_payload', false)
                    ? DataSanitizer::sanitizePayload($request->getAllInput())
                    : null,
                'response_code' => $responseCode,
                'processing_time' => round($processingTime * 1000, 2),
                'context' => $this->requestContext($request),
                'occurred_at' => new \DateTimeImmutable,
            ];

            $this->auditLogRepo->create($logData);

        } catch (\Throwable $e) {
            $this->logger->error('Failed to log request', [
                'error_type' => $e::class,
                'request_id' => $request->getRequestId(),
            ]);
        }
    }

    public function logWafAnalysis(
        RequestInterface $request,
        int $responseCode,
        array $analysis,
        float $processingTime,
        ?string $userId = null,
        ?string $sessionId = null,
    ): void {
        try {
            $logData = [
                'app_id' => $this->config->getAppId() ?? $this->config->getAppName(),
                'event_type' => 'waf_analysis',
                'user_id' => $userId,
                'session_id' => DataSanitizer::hashSessionId($sessionId, $this->config->getAppKey()),
                'ip_address' => $request->getIp(),
                'user_agent' => DataSanitizer::sanitizeText($request->getUserAgent(), 1000),
                'url' => DataSanitizer::sanitizeUrl($request->getFullUrl()),
                'method' => substr($request->getMethod(), 0, 10),
                'payload' => [
                    'waf_analysis' => DataSanitizer::sanitizePayload($analysis),
                    'processing_time_ms' => $processingTime,
                ],
                'context' => $this->requestContext($request),
                'response_code' => $responseCode,
                'processing_time' => round($processingTime, 3),
                'occurred_at' => new \DateTimeImmutable,
            ];

            $this->auditLogRepo->create($logData);

        } catch (\Throwable $e) {
            $this->logger->error('Failed to log WAF analysis', [
                'error_type' => $e::class,
                'request_id' => $request->getRequestId(),
            ]);
        }
    }

    public function logBlockedRequest(
        RequestInterface $request,
        array $analysis,
        ?string $userId = null,
        ?string $sessionId = null,
    ): void {
        try {
            $wafRule = null;
            if (isset($analysis['rule_id'])) {
                $wafRule = $this->wafRuleRepo->findByRuleId($analysis['rule_id']);
            }

            $blockedData = [
                'ip_address' => $request->getIp(),
                'user_agent' => DataSanitizer::sanitizeText($request->getUserAgent(), 1000),
                'url' => DataSanitizer::sanitizeUrl(
                    $request->getFullUrl(),
                    (bool) config('cybear.audit.capture_query_values', false),
                ),
                'method' => substr($request->getMethod(), 0, 10),
                'headers' => config('cybear.audit.capture_headers', false)
                    ? DataSanitizer::sanitizeHeaders($request->getHeaders())
                    : null,
                'payload' => config('cybear.audit.capture_payload', false)
                    ? DataSanitizer::sanitizePayload($request->getAllInput())
                    : null,
                'waf_rule_id' => $wafRule ? ($wafRule['id'] ?? null) : null,
                'waf_rule_key' => isset($analysis['rule_id']) ? (string) $analysis['rule_id'] : null,
                'reason' => DataSanitizer::sanitizeText(
                    (string) ($analysis['block_reason'] ?? 'WAF rule triggered'),
                    255,
                ),
                'incident_id' => $analysis['incident_id'] ?? null,
                'session_id' => DataSanitizer::hashSessionId($sessionId, $this->config->getAppKey()),
                'user_id' => $userId,
                'blocked_at' => new \DateTimeImmutable,
            ];

            $this->blockedRequestRepo->create($blockedData);

            if (! $wafRule) {
                $this->logger->warning('Blocked request logged without WAF rule reference', [
                    'rule_id' => $analysis['rule_id'] ?? 'unknown',
                    'request_id' => $request->getRequestId(),
                ]);
            }

            // Also create audit log entry
            $this->logSecurityEvent('request_blocked', $request, [
                'block_reason' => $blockedData['reason'],
                'waf_rule_id' => $blockedData['waf_rule_id'],
                'incident_id' => $analysis['incident_id'] ?? null,
                'analysis' => DataSanitizer::sanitizePayload($analysis),
                'request_id' => $request->getRequestId(),
            ], $userId, $sessionId);

        } catch (\Throwable $e) {
            $this->logger->error('Failed to log blocked request', [
                'error_type' => $e::class,
                'request_id' => $request->getRequestId(),
            ]);
        }
    }

    public function logSecurityEvent(
        string $eventType,
        RequestInterface $request,
        array $context = [],
        ?string $userId = null,
        ?string $sessionId = null,
    ): void {
        try {
            $logData = [
                'app_id' => $this->config->getAppId() ?? $this->config->getAppName(),
                'event_type' => $eventType,
                'user_id' => $userId,
                'session_id' => DataSanitizer::hashSessionId($sessionId, $this->config->getAppKey()),
                'ip_address' => $request->getIp(),
                'user_agent' => DataSanitizer::sanitizeText($request->getUserAgent(), 1000),
                'url' => DataSanitizer::sanitizeUrl(
                    $request->getFullUrl(),
                    (bool) config('cybear.audit.capture_query_values', false),
                ),
                'method' => substr($request->getMethod(), 0, 10),
                'payload' => DataSanitizer::sanitizePayload($context),
                'context' => $this->requestContext($request),
                'occurred_at' => new \DateTimeImmutable,
            ];

            $this->auditLogRepo->create($logData);

        } catch (\Throwable $e) {
            $this->logger->error('Failed to log security event', [
                'error_type' => $e::class,
                'event_type' => $eventType,
            ]);
        }
    }

    public function logAuthenticationEvent(
        string $eventType,
        RequestInterface $request,
        ?string $userId = null,
        ?string $userEmail = null,
        ?string $sessionId = null,
        array $context = [],
    ): void {
        if (! $this->config->isAuditEnabled() || ! $this->config->isAuditLogAuthEnabled()) {
            return;
        }

        try {
            $logData = [
                'app_id' => $this->config->getAppId() ?? $this->config->getAppName(),
                'event_type' => $eventType,
                'user_id' => $userId,
                'session_id' => DataSanitizer::hashSessionId($sessionId, $this->config->getAppKey()),
                'ip_address' => $request->getIp(),
                'user_agent' => DataSanitizer::sanitizeText($request->getUserAgent(), 1000),
                'url' => DataSanitizer::sanitizeUrl(
                    $request->getFullUrl(),
                    (bool) config('cybear.audit.capture_query_values', false),
                ),
                'method' => substr($request->getMethod(), 0, 10),
                'payload' => DataSanitizer::sanitizePayload(array_merge($context, [
                    'user_email_hash' => $userEmail
                        ? hash_hmac('sha256', strtolower(trim($userEmail)), $this->config->getAppKey() ?: 'cybear')
                        : null,
                ])),
                'occurred_at' => new \DateTimeImmutable,
                'context' => $this->requestContext($request),
            ];

            $this->auditLogRepo->create($logData);

        } catch (\Throwable $e) {
            $this->logger->error('Failed to log authentication event', [
                'error_type' => $e::class,
                'event_type' => $eventType,
            ]);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function requestContext(RequestInterface $request): array
    {
        $context = ['request_id' => $request->getRequestId()];
        $correlation = $request->getDastCorrelation();
        if ($correlation !== null) {
            $context['dast_correlation'] = DataSanitizer::sanitizePayload($correlation);
        }

        return $context;
    }
}
