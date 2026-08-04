<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use CybearCare\LaravelSecurity\Adapter\LaravelRequestAdapter;
use CybearCare\LaravelSecurity\Core\Audit\AuditLogger;
use CybearCare\LaravelSecurity\Core\Waf\WafEngine;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class WafMiddleware
{
    public function __construct(
        protected WafEngine $wafEngine,
        protected AuditLogger $auditLogger,
        protected DastCorrelationMiddleware $dastCorrelation,
    ) {}

    public function handle(Request $request, Closure $next)
    {
        if (! config('cybear.enabled', false) || ! config('cybear.waf.enabled', true)) {
            return $next($request);
        }

        $requestId = $this->requestId($request);
        $startedAt = microtime(true);
        $adapter = new LaravelRequestAdapter($request);
        $correlation = $this->dastCorrelation->process($request);

        try {
            $analysis = $this->analyze($request, $adapter);
        } catch (Throwable $exception) {
            Log::error('WAF analysis failed; configured failure policy was applied', [
                'error_type' => $exception::class,
                'route' => $request->route()?->getName(),
                'request_id' => $requestId,
            ]);
            $failureMode = (string) config('cybear.waf.failure_mode', 'allow');
            $analysis = [
                'action' => $failureMode === 'block' ? 'block' : 'allow',
                'rule_id' => 'cybear.engine_failure',
                'block_reason' => 'The web application firewall could not complete analysis.',
                'matched_rules' => [],
                'risk_score' => 0,
                'rules_evaluated' => 0,
                'degraded' => true,
            ];
        }
        $analysis['request_id'] = $requestId;
        if (($correlation['status'] ?? null) === 'accepted') {
            $analysis['dast_correlation'] = $correlation['context'];
        }

        if (($analysis['action'] ?? 'allow') === 'block') {
            return $this->dastCorrelation->decorateResponse(
                $this->handleBlockedRequest($request, $adapter, $analysis),
                $correlation,
            );
        }

        if (($analysis['action'] ?? 'allow') === 'redirect') {
            $response = $this->handleRedirect($request, $adapter, $analysis);
            $this->persistWafResult($request, $adapter, $response, $analysis, $startedAt);

            return $this->dastCorrelation->decorateResponse($response, $correlation);
        }

        if (($analysis['action'] ?? 'allow') === 'challenge' && ! $this->isChallengeCompleted($request)) {
            if (! config('cybear.waf.challenge_enabled', false)
                || ! $request->hasSession()
                || $request->expectsJson()
                || ! $request->isMethod('GET')) {
                $analysis['block_reason'] = 'Interactive challenge is unavailable for this request';

                return $this->dastCorrelation->decorateResponse(
                    $this->handleBlockedRequest($request, $adapter, $analysis),
                    $correlation,
                );
            }

            $response = $this->showChallengePage($request, $analysis);
            $this->persistWafResult($request, $adapter, $response, $analysis, $startedAt);

            return $this->dastCorrelation->decorateResponse($response, $correlation);
        }

        $response = $next($request);
        $response->headers->set('X-Cybear-Request-Id', $requestId);

        $this->persistWafResult($request, $adapter, $response, $analysis, $startedAt);

        return $this->dastCorrelation->decorateResponse($response, $correlation);
    }

    protected function analyze(Request $request, LaravelRequestAdapter $adapter): array
    {
        $maximum = max(0, (int) config('cybear.waf.max_request_size', 10 * 1024 * 1024));
        $contentLength = max(0, (int) $request->server('CONTENT_LENGTH', 0));
        $bodyLength = strlen((string) $request->getContent());
        $observedLength = max($contentLength, $bodyLength);

        if ($maximum > 0 && $observedLength > $maximum) {
            $analysis = [
                'action' => 'block',
                'rule_id' => 'cybear.request_size',
                'block_reason' => 'Request body exceeds the configured size limit',
                'matched_rules' => [],
                'risk_score' => 7,
                'rules_evaluated' => 0,
                'observed_request_bytes' => $observedLength,
            ];

            if (config('cybear.waf.mode', 'monitor') === 'monitor') {
                $analysis['original_action'] = 'block';
                $analysis['action'] = 'allow';
            }

            return $analysis;
        }

        return $this->wafEngine->analyzeRequest($adapter);
    }

    protected function handleBlockedRequest(
        Request $request,
        LaravelRequestAdapter $adapter,
        array $analysis,
    ): Response {
        $incidentId = (string) Str::uuid();
        $analysis['incident_id'] = $incidentId;

        try {
            $this->auditLogger->logBlockedRequest(
                $adapter,
                $analysis,
                Auth::id() ? (string) Auth::id() : null,
                $this->sessionId($request),
            );
        } catch (Throwable $exception) {
            Log::warning('Failed to persist blocked-request telemetry', [
                'error_type' => $exception::class,
                'incident_id' => $incidentId,
            ]);
        }

        $headers = [
            'X-Cybear-Blocked' => 'true',
            'X-Cybear-Incident-Id' => $incidentId,
            'X-Cybear-Request-Id' => $this->requestId($request),
            'Cache-Control' => 'no-store, private',
            'X-Content-Type-Options' => 'nosniff',
        ];
        if (config('cybear.waf.expose_rule_header', false)) {
            $headers['X-Cybear-Rule'] = $analysis['rule_id'] ?? 'unknown';
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Request blocked by the application security policy.',
                'incident_id' => $incidentId,
            ], 403, $headers);
        }

        try {
            $content = $this->getBlockPageContent($analysis);
        } catch (Throwable $exception) {
            Log::warning('Failed to render the custom WAF block page', [
                'error_type' => $exception::class,
                'incident_id' => $incidentId,
            ]);
            $content = '<!doctype html><title>Forbidden</title><h1>403 Forbidden</h1>'
                .'<p>This request was blocked.</p><p>Incident ID: '
                .e($incidentId)
                .'</p>';
        }

        return new Response($content, 403, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'",
        ] + $headers);
    }

    protected function handleRedirect(
        Request $request,
        LaravelRequestAdapter $adapter,
        array $analysis,
    ): Response {
        $parameters = is_array($analysis['action_params'] ?? null)
            ? $analysis['action_params']
            : [];
        $location = $parameters['location'] ?? $parameters['url'] ?? null;
        $status = (int) ($parameters['status'] ?? 302);

        if (! is_string($location)
            || ! str_starts_with($location, '/')
            || str_starts_with($location, '//')
            || str_contains($location, '\\')
            || preg_match('/[\x00-\x1F\x7F]/', $location) === 1
            || ! in_array($status, [301, 302, 303, 307, 308], true)) {
            $analysis['block_reason'] = 'Invalid WAF redirect action';

            return $this->handleBlockedRequest($request, $adapter, $analysis);
        }

        $headers = [
            'X-Cybear-Request-Id' => $this->requestId($request),
            'Cache-Control' => 'no-store, private',
        ];
        if (config('cybear.waf.expose_rule_header', false)) {
            $headers['X-Cybear-Rule'] = $analysis['rule_id'] ?? 'unknown';
        }

        return redirect()->to($location, $status, $headers);
    }

    protected function isChallengeCompleted(Request $request): bool
    {
        if (! $request->hasSession()) {
            return false;
        }

        $now = now()->getTimestamp();
        $passedAt = $request->session()->get('cybear_challenge_passed_at');
        $binding = $request->session()->get('cybear_challenge_binding');
        if ($request->session()->get('cybear_challenge_passed', false)
            && is_int($passedAt)
            && $passedAt <= $now
            && $passedAt >= $now - 3600
            && is_string($binding)
            && hash_equals($binding, $this->challengeBinding($request))) {
            return true;
        }

        if (! $request->filled('cybear_challenge_token')
            || ! $request->filled('cybear_challenge_answer')) {
            return false;
        }

        $expected = $request->session()->get('cybear_challenge_token');
        $expectedAnswer = $request->session()->get('cybear_challenge_answer');
        $createdAt = $request->session()->get('cybear_challenge_token_created_at');

        if (! is_string($expected)
            || ! is_int($expectedAnswer)
            || ! is_int($createdAt)
            || $createdAt > $now
            || $createdAt < $now - 300) {
            return false;
        }

        $submittedAnswer = filter_var(
            $request->input('cybear_challenge_answer'),
            FILTER_VALIDATE_INT,
        );
        $valid = hash_equals($expected, (string) $request->input('cybear_challenge_token', ''))
            && $submittedAnswer === $expectedAnswer;

        $request->session()->forget([
            'cybear_challenge_token',
            'cybear_challenge_answer',
            'cybear_challenge_token_created_at',
        ]);

        if ($valid) {
            $request->session()->put([
                'cybear_challenge_passed' => true,
                'cybear_challenge_passed_at' => $now,
                'cybear_challenge_binding' => $this->challengeBinding($request),
            ]);
        }

        return $valid;
    }

    protected function showChallengePage(Request $request, array $analysis): Response
    {
        $challengeToken = Str::random(32);
        $left = random_int(2, 20);
        $right = random_int(2, 20);
        $request->session()->put([
            'cybear_challenge_token' => $challengeToken,
            'cybear_challenge_answer' => $left + $right,
            'cybear_challenge_token_created_at' => now()->getTimestamp(),
        ]);

        $content = view('cybear::waf.challenge', [
            'analysis' => $analysis,
            'challenge_token' => $challengeToken,
            'challenge_left' => $left,
            'challenge_right' => $right,
        ])->render();

        return new Response($content, 403, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'X-Cybear-Challenge' => 'true',
            'X-Cybear-Request-Id' => $this->requestId($request),
            'Cache-Control' => 'no-store, private',
            'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ]);
    }

    protected function getBlockPageContent(array $analysis): string
    {
        $customBlockPage = config('cybear.waf.block_page');

        if (is_string($customBlockPage) && $customBlockPage !== '' && view()->exists($customBlockPage)) {
            return view($customBlockPage, compact('analysis'))->render();
        }

        return view('cybear::waf.blocked', compact('analysis'))->render();
    }

    protected function logWafResult(
        Request $request,
        LaravelRequestAdapter $adapter,
        Response $response,
        array $analysis,
        float $startedAt,
    ): void {
        if (empty($analysis['matched_rules'])
            && empty($analysis['original_action'])
            && empty($analysis['degraded'])
            && empty($analysis['dast_correlation'])
            && ! config('cybear.waf.log_allowed_requests', false)) {
            return;
        }

        $processingTime = isset($analysis['processing_time'])
            ? (float) $analysis['processing_time']
            : (microtime(true) - $startedAt) * 1000;

        $this->auditLogger->logWafAnalysis(
            $adapter,
            $response->getStatusCode(),
            $analysis,
            $processingTime,
            Auth::id() ? (string) Auth::id() : null,
            $this->sessionId($request),
        );

        if (config('cybear.debugging.performance_logging', false)) {
            Log::debug('WAF processing time', [
                'route' => $request->route()?->getName(),
                'request_id' => $this->requestId($request),
                'processing_time_ms' => round($processingTime, 2),
                'rules_evaluated' => $analysis['rules_evaluated'] ?? 0,
                'action' => $analysis['action'] ?? 'allow',
            ]);
        }
    }

    protected function persistWafResult(
        Request $request,
        LaravelRequestAdapter $adapter,
        Response $response,
        array $analysis,
        float $startedAt,
    ): void {
        try {
            $this->logWafResult($request, $adapter, $response, $analysis, $startedAt);
        } catch (Throwable $exception) {
            Log::warning('Failed to persist WAF telemetry', [
                'error_type' => $exception::class,
                'route' => $request->route()?->getName(),
                'request_id' => $this->requestId($request),
            ]);
        }
    }

    protected function sessionId(Request $request): ?string
    {
        return $request->hasSession() ? $request->session()->getId() : null;
    }

    protected function requestId(Request $request): string
    {
        $requestId = $request->attributes->get('cybear_request_id');
        if (! is_string($requestId) || $requestId === '') {
            $requestId = (string) Str::uuid();
            $request->attributes->set('cybear_request_id', $requestId);
        }

        return $requestId;
    }

    protected function challengeBinding(Request $request): string
    {
        return hash_hmac(
            'sha256',
            ($request->ip() ?? '0.0.0.0')."\n".($request->userAgent() ?? ''),
            (string) config('app.key', 'cybear'),
        );
    }
}
