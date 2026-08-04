<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use CybearCare\LaravelSecurity\Core\Protection\SensitiveFileGuard;

class SensitiveFileMiddleware
{
    protected SensitiveFileGuard $guard;

    public function __construct(SensitiveFileGuard $guard)
    {
        $this->guard = $guard;
    }

    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.enabled', false) || !config('cybear.sensitive_files.enabled', true)) {
            return $next($request);
        }

        $result = $this->guard->check($request->getPathInfo());

        if ($result['blocked']) {
            Log::warning('CybearCare: Blocked sensitive file access', [
                'path' => $request->getPathInfo(),
                'ip' => $request->ip(),
                'reason' => $result['reason'],
            ]);

            return new Response('Not Found', 404, [
                'Content-Type' => 'text/plain',
                'X-Cybear-Blocked' => 'sensitive-file',
            ]);
        }

        return $next($request);
    }
}
