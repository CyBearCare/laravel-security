<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RateLimitMiddleware
{
    public function __construct(protected RateLimiter $limiter)
    {
    }

    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.enabled', false)
            || !config('cybear.rate_limiting.enabled', false)
            || (config('cybear.rate_limiting.exclude_authenticated', false) && Auth::check())) {
            return $next($request);
        }

        $limits = [
            'minute' => [(int) config('cybear.rate_limiting.requests_per_minute', 60), 60],
            'hour' => [(int) config('cybear.rate_limiting.requests_per_hour', 1000), 3600],
            'day' => [(int) config('cybear.rate_limiting.requests_per_day', 10000), 86400],
        ];

        foreach ($limits as $period => [$maximum, $decay]) {
            $key = $this->key($request, $period);
            if ($maximum > 0 && $this->limiter->tooManyAttempts($key, $maximum)) {
                return $this->rateLimitExceededResponse(
                    $request,
                    $period,
                    $maximum,
                    max(1, $this->limiter->availableIn($key)),
                );
            }
        }

        foreach ($limits as $period => [$maximum, $decay]) {
            if ($maximum > 0) {
                $this->limiter->hit($this->key($request, $period), $decay);
            }
        }

        return $next($request);
    }

    protected function key(Request $request, string $period): string
    {
        $identity = Auth::id() !== null
            ? 'user:' . Auth::id()
            : 'ip:' . ($request->ip() ?? 'unknown');

        return 'cybear:' . hash('sha256', $identity) . ':' . $period;
    }

    protected function rateLimitExceededResponse(
        Request $request,
        string $period,
        int $limit,
        int $retryAfter,
    ): Response {
        $message = "Too many requests. Limit: {$limit} per {$period}.";
        $headers = [
            'Retry-After' => (string) $retryAfter,
            'X-Cybear-Rate-Limited' => 'true',
        ];

        if ($request->expectsJson()) {
            return response()->json([
                'message' => $message,
                'retry_after' => $retryAfter,
            ], 429, $headers);
        }

        return response($message, 429, $headers);
    }
}
