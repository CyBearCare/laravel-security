<?php

namespace CybearCare\LaravelSecurity\Middleware;

use Closure;
use CybearCare\LaravelSecurity\Services\SyncOrchestrator;
use Illuminate\Http\Request;


class SyncMiddleware
{
    protected SyncOrchestrator $syncOrchestrator;

    public function __construct(SyncOrchestrator $syncOrchestrator)
    {
        $this->syncOrchestrator = $syncOrchestrator;
    }

    public function handle(Request $request, Closure $next)
    {
        return $next($request);
    }

    /**
     * Runs after the response has been sent to the browser.
     */
    public function terminate(Request $request, $response): void
    {
        if ($this->syncOrchestrator->shouldRun()) {
            $this->syncOrchestrator->runDueSyncs('request');
        }
    }
}
