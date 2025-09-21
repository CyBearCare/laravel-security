<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use CybearCare\LaravelSecurity\Services\AuditLogger;
use Illuminate\Support\Facades\Auth;

class AuditLogMiddleware
{
    protected AuditLogger $auditLogger;

    public function __construct(AuditLogger $auditLogger)
    {
        $this->auditLogger = $auditLogger;
    }

    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.audit.enabled', true)) {
            return $next($request);
        }

        if ($this->shouldSkipLogging($request)) {
            return $next($request);
        }

        $startTime = microtime(true);
        
        $response = $next($request);
        
        $processingTime = microtime(true) - $startTime;

        $this->auditLogger->logRequest($request, $response, $processingTime);

        return $response;
    }

    protected function shouldSkipLogging(Request $request): bool
    {
        $excludedRoutes = config('cybear.audit.excluded_routes', []);
        $excludedIps = config('cybear.audit.excluded_ips', []);

        // Check excluded routes
        foreach ($excludedRoutes as $pattern) {
            if ($request->is($pattern)) {
                return true;
            }
        }

        // Check excluded IPs
        if (in_array($request->ip(), $excludedIps)) {
            return true;
        }

        // Skip static assets in production
        if (app()->environment('production') && $this->isStaticAsset($request)) {
            return true;
        }

        return false;
    }

    protected function isStaticAsset(Request $request): bool
    {
        $staticExtensions = ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot'];
        $path = $request->path();
        
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        
        return in_array(strtolower($extension), $staticExtensions);
    }
}