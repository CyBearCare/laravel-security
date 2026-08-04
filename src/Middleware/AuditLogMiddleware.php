<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use CybearCare\LaravelSecurity\Core\Audit\AuditLogger;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Adapter\LaravelRequestAdapter;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class AuditLogMiddleware
{
    protected AuditLogger $auditLogger;
    protected CybearConfig $config;

    public function __construct(AuditLogger $auditLogger, CybearConfig $config)
    {
        $this->auditLogger = $auditLogger;
        $this->config = $config;
    }

    public function handle(Request $request, Closure $next)
    {
        if (!config('cybear.enabled', false) || !config('cybear.audit.enabled', true)) {
            return $next($request);
        }

        if ($this->shouldSkipLogging($request)) {
            return $next($request);
        }

        $requestId = $request->attributes->get('cybear_request_id');
        if (!is_string($requestId) || $requestId === '') {
            $requestId = (string) Str::uuid();
            $request->attributes->set('cybear_request_id', $requestId);
        }

        $startTime = microtime(true);
        $response = null;
        $failure = null;
        try {
            $response = $next($request);
        } catch (Throwable $exception) {
            $failure = $exception;
        }

        try {
            $this->auditLogger->logRequest(
                new LaravelRequestAdapter($request),
                $response?->getStatusCode() ?? 500,
                microtime(true) - $startTime,
                Auth::id() ? (string) Auth::id() : null,
                $request->hasSession() ? $request->session()->getId() : null,
            );
        } catch (Throwable $exception) {
            Log::warning('Failed to persist Cybear audit telemetry', [
                'error_type' => $exception::class,
                'route' => $request->route()?->getName(),
                'request_id' => $requestId,
            ]);
        }

        if ($failure instanceof Throwable) {
            throw $failure;
        }

        $response->headers->set('X-Cybear-Request-Id', $requestId);

        return $response;
    }

    protected function shouldSkipLogging(Request $request): bool
    {
        $excludedRoutes = $this->config->getAuditExcludedRoutes();
        $excludedIps = $this->config->getAuditExcludedIps();

        foreach ($excludedRoutes as $pattern) {
            if ($request->is($pattern)) {
                return true;
            }
        }

        if (in_array($request->ip(), $excludedIps, true)) {
            return true;
        }

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

        return in_array(strtolower($extension), $staticExtensions, true);
    }
}
