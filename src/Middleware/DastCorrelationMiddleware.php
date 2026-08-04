<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use CybearCare\LaravelSecurity\Adapter\LaravelRequestAdapter;
use CybearCare\LaravelSecurity\Core\Audit\AuditLogger;
use CybearCare\LaravelSecurity\Core\Dast\DastCorrelationVerifier;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class DastCorrelationMiddleware
{
    public function __construct(
        private readonly DastCorrelationVerifier $verifier,
        private readonly AuditLogger $auditLogger,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('cybear.enabled', false)) {
            return $next($request);
        }

        $result = $this->process($request);
        $response = $next($request);

        return $this->decorateResponse($response, $result);
    }

    /**
     * @return array{status: string, reason?: string, context?: array<string, string>}
     */
    public function process(Request $request): array
    {
        $processed = $request->attributes->get('cybear_dast_result');
        if (is_array($processed)) {
            return $processed;
        }

        $requestId = $request->attributes->get('cybear_request_id');
        if (! is_string($requestId) || $requestId === '') {
            $requestId = (string) Str::uuid();
            $request->attributes->set('cybear_request_id', $requestId);
        }

        $adapter = new LaravelRequestAdapter($request);
        try {
            $result = $this->verifier->verify($adapter);
        } catch (Throwable $exception) {
            Log::warning('DAST correlation verification failed', [
                'error_type' => $exception::class,
                'request_id' => $requestId,
            ]);
            $result = ['status' => 'rejected', 'reason' => 'verification_failure'];
        } finally {
            $request->headers->remove(DastCorrelationVerifier::HEADER);
        }

        if (($result['status'] ?? null) === 'accepted') {
            $request->attributes->set('cybear_dast_correlation', $result['context']);
        } elseif (($result['status'] ?? null) === 'rejected') {
            $this->logRejected($request, $adapter, $result);
        }

        $request->attributes->set('cybear_dast_result', $result);

        return $result;
    }

    public function decorateResponse(Response $response, array $result): Response
    {
        if (($result['status'] ?? null) === 'accepted') {
            $response->headers->set('X-Cybear-Scan-Correlation', 'accepted');
        }

        return $response;
    }

    private function logRejected(
        Request $request,
        LaravelRequestAdapter $adapter,
        array $result,
    ): void {
        $reason = (string) ($result['reason'] ?? 'unknown');
        try {
            $shouldLog = $this->verifier->shouldLogRejection($adapter, $reason);
        } catch (Throwable) {
            $shouldLog = false;
        }

        if (! $shouldLog) {
            return;
        }

        $this->auditLogger->logSecurityEvent(
            'dast_correlation_rejected',
            $adapter,
            ['reason' => $reason],
            Auth::id() ? (string) Auth::id() : null,
            $request->hasSession() ? $request->session()->getId() : null,
        );
    }
}
