<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use CybearCare\LaravelSecurity\Models\AuditLog;
use CybearCare\LaravelSecurity\Models\BlockedRequest;

class AuditLogger
{
    protected CybearApiClient $apiClient;

    public function __construct(CybearApiClient $apiClient)
    {
        $this->apiClient = $apiClient;
    }

    public function logRequest($request, $response, float $processingTime): void
    {
        if (!config('cybear.audit.log_requests', true)) {
            return;
        }

        try {
            $logData = [
                'app_id' => config('cybear.app_id', config('app.name')),
                'event_type' => 'http_request',
                'user_id' => Auth::id(),
                'session_id' => $this->hashSessionId($request->session()->getId()),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'headers' => $this->sanitizeHeaders($request->headers->all()),
                'payload' => $this->sanitizePayload($request->all()),
                'response_code' => $response->getStatusCode(),
                'processing_time' => round($processingTime * 1000, 2), // Convert to milliseconds
                'occurred_at' => now(),
            ];

            AuditLog::create($logData);

        } catch (\Exception $e) {
            Log::error('Failed to log request', [
                'error' => $e->getMessage(),
                'url' => $request->fullUrl(),
            ]);
        }
    }

    public function logWafAnalysis($request, $response, array $analysis, float $processingTime): void
    {
        try {
            $logData = [
                'app_id' => config('cybear.app_id', config('app.name')),
                'event_type' => 'waf_analysis',
                'user_id' => Auth::id(),
                'session_id' => $this->hashSessionId($request->session()->getId()),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'payload' => [
                    'waf_analysis' => $analysis,
                    'processing_time_ms' => $processingTime,
                ],
                'response_code' => $response->getStatusCode(),
                'processing_time' => $processingTime / 1000, // Convert to seconds for consistency
                'occurred_at' => now(),
            ];

            AuditLog::create($logData);

        } catch (\Exception $e) {
            Log::error('Failed to log WAF analysis', [
                'error' => $e->getMessage(),
                'url' => $request->fullUrl(),
            ]);
        }
    }

    public function logBlockedRequest($request, array $analysis): void
    {
        try {
            // Find the WAF rule by rule_id
            $wafRule = null;
            if (isset($analysis['rule_id'])) {
                $wafRule = \CybearCare\LaravelSecurity\Models\WafRule::where('rule_id', $analysis['rule_id'])->first();
            }
            
            $blockedData = [
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'headers' => $this->sanitizeHeaders($request->headers->all()),
                'payload' => $this->sanitizePayload($request->all()),
                'waf_rule_id' => $wafRule ? $wafRule->id : null,
                'reason' => $analysis['block_reason'] ?? 'WAF rule triggered',
                'incident_id' => $analysis['incident_id'] ?? null,
                'session_id' => $this->hashSessionId($request->session()->getId()),
                'user_id' => Auth::id(),
                'blocked_at' => now(),
            ];

            // Only create blocked request if we have a valid WAF rule
            if ($wafRule) {
                BlockedRequest::create($blockedData);
            } else {
                Log::warning('Blocked request not logged - WAF rule not found', [
                    'rule_id' => $analysis['rule_id'] ?? 'unknown',
                    'ip' => $request->ip(),
                    'url' => $request->fullUrl()
                ]);
            }

            // Also create audit log entry
            $this->logSecurityEvent('request_blocked', $request, [
                'block_reason' => $blockedData['reason'],
                'waf_rule_id' => $blockedData['waf_rule_id'],
                'incident_id' => $analysis['incident_id'] ?? null,
                'analysis' => $analysis,
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to log blocked request', [
                'error' => $e->getMessage(),
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
            ]);
        }
    }

    public function logSecurityEvent(string $eventType, $request, array $context = []): void
    {
        try {
            $logData = [
                'app_id' => config('cybear.app_id', config('app.name')),
                'event_type' => $eventType,
                'user_id' => Auth::id(),
                'session_id' => $this->hashSessionId($request->session()->getId()),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'payload' => $context,
                'occurred_at' => now(),
            ];

            AuditLog::create($logData);

        } catch (\Exception $e) {
            Log::error('Failed to log security event', [
                'error' => $e->getMessage(),
                'event_type' => $eventType,
            ]);
        }
    }

    public function logAuthenticationEvent(string $eventType, $request, $user = null, array $context = []): void
    {
        if (!config('cybear.audit.log_authentication', true)) {
            return;
        }

        try {
            $logData = [
                'app_id' => config('cybear.app_id', config('app.name')),
                'event_type' => $eventType,
                'user_id' => $user ? $user->id : Auth::id(),
                'session_id' => $this->hashSessionId($request->session()->getId()),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'payload' => array_merge($context, [
                    'user_email' => $user->email ?? null,
                ]),
                'occurred_at' => now(),
            ];

            AuditLog::create($logData);

        } catch (\Exception $e) {
            Log::error('Failed to log authentication event', [
                'error' => $e->getMessage(),
                'event_type' => $eventType,
            ]);
        }
    }

    protected function sanitizeHeaders(array $headers): array
    {
        $sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
        
        foreach ($headers as $key => $value) {
            if (in_array(strtolower($key), $sensitiveHeaders)) {
                $headers[$key] = ['[REDACTED]'];
            }
        }

        return $headers;
    }

    protected function sanitizePayload(array $payload): array
    {
        $sensitiveFields = ['password', 'password_confirmation', 'token', 'secret', 'api_key', 
                           'credit_card', 'cvv', 'ssn', 'private_key', 'auth_token',
                           'access_token', 'refresh_token', 'client_secret'];
        
        return $this->recursiveSanitize($payload, $sensitiveFields);
    }
    
    protected function recursiveSanitize(array $data, array $sensitiveFields): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->recursiveSanitize($value, $sensitiveFields);
            } elseif (is_string($key)) {
                foreach ($sensitiveFields as $sensitive) {
                    if (stripos($key, $sensitive) !== false) {
                        $data[$key] = '[REDACTED]';
                        break;
                    }
                }
            }
        }
        
        return $data;
    }
    
    /**
     * Hash session ID for privacy
     */
    protected function hashSessionId(?string $sessionId): ?string
    {
        if (!$sessionId) {
            return null;
        }
        
        // Use a consistent hash that allows correlation within same session
        // but doesn't expose the actual session ID
        return substr(hash('sha256', $sessionId . config('app.key')), 0, 16);
    }


}