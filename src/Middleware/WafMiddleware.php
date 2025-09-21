<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use CybearCare\LaravelSecurity\Services\WafEngine;
use CybearCare\LaravelSecurity\Services\AuditLogger;
use Illuminate\Support\Facades\Log;

class WafMiddleware
{
    protected WafEngine $wafEngine;
    protected AuditLogger $auditLogger;

    public function __construct(WafEngine $wafEngine, AuditLogger $auditLogger)
    {
        $this->wafEngine = $wafEngine;
        $this->auditLogger = $auditLogger;
    }

    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.waf.enabled', true)) {
            return $next($request);
        }

        $startTime = microtime(true);

        try {
            $analysis = $this->wafEngine->analyzeRequest($request);

            if ($analysis['action'] === 'block') {
                return $this->handleBlockedRequest($request, $analysis);
            }

            if ($analysis['action'] === 'challenge') {
                return $this->handleChallenge($request, $analysis);
            }

            $response = $next($request);

            $this->logWafResult($request, $response, $analysis, $startTime);

            return $response;

        } catch (\Exception $e) {
            Log::error('WAF middleware error', [
                'error' => $e->getMessage(),
                'url' => $request->fullUrl(),
                'ip' => $request->ip(),
                // Only log trace in debug mode to prevent information disclosure
                'trace' => config('app.debug') ? $e->getTraceAsString() : 'Trace disabled in production'
            ]);

            // Fail open - allow request to continue if WAF fails
            return $next($request);
        }
    }

    protected function handleBlockedRequest(Request $request, array $analysis): Response
    {
        // Generate incident ID
        $incidentId = (string) \Illuminate\Support\Str::uuid();
        $analysis['incident_id'] = $incidentId;
        
        $this->auditLogger->logBlockedRequest($request, $analysis);

        $blockPageContent = $this->getBlockPageContent($analysis);
        
        return response($blockPageContent, 403, [
            'Content-Type' => 'text/html',
            'X-Cybear-Blocked' => 'true',
            'X-Cybear-Rule' => $analysis['rule_id'] ?? 'unknown',
            'X-Cybear-Incident-Id' => $incidentId,
        ]);
    }

    protected function handleChallenge(Request $request, array $analysis): Response
    {
        // Check if challenge was already passed to prevent infinite loops
        if ($request->session()->get('cybear_challenge_passed', false)) {
            $request->session()->forget('cybear_challenge_passed');
            return app()->handle($request);
        }
        
        if ($this->validateChallengeResponse($request)) {
            // Mark challenge as passed
            $request->session()->put('cybear_challenge_passed', true);
            $request->session()->put('cybear_challenge_passed_at', now());
            
            // Continue with the original request
            return app()->handle($request);
        }

        $challengeContent = $this->getChallengePageContent($analysis);
        
        return response($challengeContent, 200, [
            'Content-Type' => 'text/html',
            'X-Cybear-Challenge' => 'true',
        ]);
    }

    protected function validateChallengeResponse(Request $request): bool
    {
        if (!$request->has('cybear_challenge_response')) {
            return false;
        }

        $response = $request->input('cybear_challenge_response');
        $expected = $request->session()->get('cybear_challenge_token');
        
        // Verify token exists and hasn't expired (5 minute timeout)
        $tokenCreatedAt = $request->session()->get('cybear_challenge_token_created_at');
        if (!$expected || !$tokenCreatedAt || now()->diffInMinutes($tokenCreatedAt) > 5) {
            return false;
        }

        // Use timing-safe comparison
        $valid = hash_equals($expected, $response ?? '');
        
        // Clear challenge token after validation attempt
        if ($valid) {
            $request->session()->forget(['cybear_challenge_token', 'cybear_challenge_token_created_at']);
        }
        
        return $valid;
    }

    protected function getBlockPageContent(array $analysis): string
    {
        $customBlockPage = config('cybear.waf.block_page');
        
        if ($customBlockPage && view()->exists($customBlockPage)) {
            return view($customBlockPage, compact('analysis'))->render();
        }

        return view('cybear::waf.blocked', compact('analysis'))->render();
    }

    protected function getChallengePageContent(array $analysis): string
    {
        $challengeToken = str()->random(32);
        session([
            'cybear_challenge_token' => $challengeToken,
            'cybear_challenge_token_created_at' => now()
        ]);

        return view('cybear::waf.challenge', [
            'analysis' => $analysis,
            'challenge_token' => $challengeToken
        ])->render();
    }

    protected function logWafResult(Request $request, $response, array $analysis, float $startTime): void
    {
        $processingTime = (microtime(true) - $startTime) * 1000; // Convert to milliseconds

        $this->auditLogger->logWafAnalysis($request, $response, $analysis, $processingTime);

        if (config('cybear.debugging.performance_logging', false)) {
            Log::debug('WAF processing time', [
                'url' => $request->fullUrl(),
                'processing_time_ms' => round($processingTime, 2),
                'rules_evaluated' => $analysis['rules_evaluated'] ?? 0,
                'action' => $analysis['action'] ?? 'allow',
            ]);
        }
    }
}