<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RateLimitMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.rate_limiting.enabled', true)) {
            return $next($request);
        }

        if ($this->shouldSkipRateLimiting($request)) {
            return $next($request);
        }

        $ip = $request->ip();
        $user = Auth::user();
        
        $limits = [
            'minute' => config('cybear.rate_limiting.requests_per_minute', 60),
            'hour' => config('cybear.rate_limiting.requests_per_hour', 1000),
            'day' => config('cybear.rate_limiting.requests_per_day', 10000),
        ];

        foreach ($limits as $period => $limit) {
            if ($this->isRateLimited($ip, $user, $period, $limit)) {
                return $this->rateLimitExceededResponse($period, $limit);
            }
        }

        $this->incrementCounters($ip, $user);

        return $next($request);
    }

    protected function shouldSkipRateLimiting(Request $request): bool
    {
        // Skip rate limiting for authenticated users if configured
        if (config('cybear.rate_limiting.exclude_authenticated', false) && Auth::check()) {
            return true;
        }

        return false;
    }

    protected function isRateLimited(string $ip, $user, string $period, int $limit): bool
    {
        $key = $this->getRateLimitKey($ip, $user, $period);
        $current = Cache::get($key, 0);

        return $current >= $limit;
    }

    protected function incrementCounters(string $ip, $user): void
    {
        $periods = [
            'minute' => 60,
            'hour' => 3600,
            'day' => 86400,
        ];

        foreach ($periods as $period => $ttl) {
            $key = $this->getRateLimitKey($ip, $user, $period);
            
            if (Cache::has($key)) {
                Cache::increment($key);
            } else {
                Cache::put($key, 1, $ttl);
            }
        }
    }

    protected function getRateLimitKey(string $ip, $user, string $period): string
    {
        $identifier = $user ? "user:{$user->id}" : "ip:{$ip}";
        $window = $this->getTimeWindow($period);
        
        return "cybear_rate_limit:{$identifier}:{$period}:{$window}";
    }

    protected function getTimeWindow(string $period): string
    {
        switch ($period) {
            case 'minute':
                return now()->format('Y-m-d H:i');
            case 'hour':
                return now()->format('Y-m-d H');
            case 'day':
                return now()->format('Y-m-d');
            default:
                return now()->format('Y-m-d H:i');
        }
    }

    protected function rateLimitExceededResponse(string $period, int $limit): Response
    {
        $retryAfter = $this->getRetryAfter($period);
        
        return response()->json([
            'error' => 'Rate limit exceeded',
            'message' => "Too many requests. Limit: {$limit} per {$period}",
            'retry_after' => $retryAfter,
        ], 429, [
            'Retry-After' => $retryAfter,
            'X-Cybear-Rate-Limited' => 'true',
        ]);
    }

    protected function getRetryAfter(string $period): int
    {
        switch ($period) {
            case 'minute':
                return 60 - now()->second;
            case 'hour':
                return 3600 - (now()->minute * 60 + now()->second);
            case 'day':
                return 86400 - (now()->hour * 3600 + now()->minute * 60 + now()->second);
            default:
                return 60;
        }
    }
}