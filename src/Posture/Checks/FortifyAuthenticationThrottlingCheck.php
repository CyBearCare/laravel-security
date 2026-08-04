<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Routing\Route;
use Throwable;

final class FortifyAuthenticationThrottlingCheck extends AbstractCheck
{
    public function __construct(private RouteSecurityInspector $inspector)
    {
    }

    public function id(): string
    {
        return 'laravel.fortify.authentication_throttling';
    }

    public function name(): string
    {
        return 'Fortify authentication throttling';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function confidence(): Confidence
    {
        return Confidence::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('fortify')) {
            return $this->skipped('Laravel Fortify is not installed.');
        }

        $checked = [];
        $unprotected = [];
        $uncertain = [];
        $resolutionFailures = 0;

        foreach ($context->routes() as $route) {
            $endpoint = $this->endpoint($route);
            if ($endpoint === null) {
                continue;
            }

            $inspection = $this->inspector->middleware($context, $route);
            $resolutionFailures += $inspection['resolution_failed'] ? 1 : 0;
            $protected = $this->inspector->hasRateLimit($inspection['middleware']);
            $source = $protected ? 'route_middleware' : null;
            $unknown = $inspection['resolution_failed'] && !$protected;

            if (!$protected && $endpoint === 'login') {
                [$protected, $source, $pipelineUnknown] = $this->loginPipelineProtection($context);
                $unknown = $unknown || $pipelineUnknown;
            }

            if (!$protected && $unknown) {
                $uncertain[] = [
                    'endpoint' => $endpoint,
                    ...$this->inspector->evidence($route),
                ];
            }

            $checked[] = [
                'endpoint' => $endpoint,
                'rate_limited' => $protected,
                'protection_source' => $source,
                ...$this->inspector->evidence($route),
            ];

            if (!$protected && !$unknown) {
                $unprotected[] = [
                    'endpoint' => $endpoint,
                    ...$this->inspector->evidence($route),
                ];
            }
        }

        $evidence = [
            'version' => $context->capabilities->packageVersion('fortify'),
            'endpoints' => $checked,
            'unprotected_endpoints' => $unprotected,
            'uncertain_endpoints' => $uncertain,
            'middleware_resolution_failure_count' => $resolutionFailures,
        ];

        if ($checked === []) {
            return $this->skipped('No Fortify login, two-factor challenge, or passkey login routes were detected.', [
                'version' => $context->capabilities->packageVersion('fortify'),
            ]);
        }

        if ($unprotected !== []) {
            return $this->fail(
                'Fortify authentication endpoints were found without a verifiable rate limit.',
                'Attach Laravel throttle middleware or a recognized rate-limiting middleware to two-factor and passkey login routes. Keep EnsureLoginIsNotThrottled in any custom Fortify login pipeline.',
                $evidence,
            );
        }

        if ($uncertain !== [] || $resolutionFailures > 0) {
            return $this->warning(
                'Fortify authentication throttling could not be fully verified.',
                'Review custom authentication pipelines and unresolved middleware, then ensure every credential, two-factor, and passkey verification path has a bounded attempt rate.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass('Fortify authentication endpoints have verifiable rate limiting.', $evidence);
    }

    private function endpoint(Route $route): ?string
    {
        if (!in_array('POST', $route->methods(), true)) {
            return null;
        }

        $action = strtolower($route->getActionName());

        return match (true) {
            str_contains(
                $action,
                'laravel\\fortify\\http\\controllers\\twofactorauthenticatedsessioncontroller@store',
            ) => 'two_factor',
            str_contains(
                $action,
                'laravel\\passkeys\\http\\controllers\\passkeylogincontroller@store',
            ) => 'passkey',
            str_contains(
                $action,
                'laravel\\fortify\\http\\controllers\\authenticatedsessioncontroller@store',
            ) => 'login',
            default => null,
        };
    }

    /**
     * @return array{bool, string|null, bool}
     */
    private function loginPipelineProtection(CheckContext $context): array
    {
        $pipeline = $context->config('fortify.pipelines.login');
        if (is_array($pipeline)) {
            foreach ($pipeline as $middleware) {
                if (is_string($middleware)
                    && ($middleware === 'EnsureLoginIsNotThrottled'
                        || str_ends_with($middleware, '\\EnsureLoginIsNotThrottled'))) {
                    return [true, 'configured_login_pipeline', false];
                }
            }

            return [false, 'configured_login_pipeline', true];
        }

        try {
            if (class_exists(\Laravel\Fortify\Fortify::class)
                && property_exists(\Laravel\Fortify\Fortify::class, 'authenticateThroughCallback')
                && \Laravel\Fortify\Fortify::$authenticateThroughCallback !== null) {
                return [false, 'custom_login_pipeline_callback', true];
            }
        } catch (Throwable) {
            return [false, null, true];
        }

        return [true, 'fortify_default_login_pipeline', false];
    }
}
