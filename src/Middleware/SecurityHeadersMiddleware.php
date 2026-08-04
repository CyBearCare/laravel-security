<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use CybearCare\LaravelSecurity\Core\Headers\SecurityHeadersManager;

class SecurityHeadersMiddleware
{
    protected SecurityHeadersManager $headersManager;

    public function __construct(SecurityHeadersManager $headersManager)
    {
        $this->headersManager = $headersManager;
    }

    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        if (!config('cybear.enabled', false) || !config('cybear.security_headers.enabled', false)) {
            return $response;
        }

        foreach ($this->headersManager->getHeaders() as $name => $value) {
            if (!$response->headers->has($name)) {
                $response->headers->set($name, $value);
            }
        }

        return $response;
    }
}
