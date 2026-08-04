<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\RouteSecurityInspector;
use CybearCare\LaravelSecurity\Posture\Severity;
use Illuminate\Routing\Route;

final class FortifyTwoFactorHardeningCheck extends AbstractCheck
{
    private const FEATURE = 'two-factor-authentication';

    public function __construct(private RouteSecurityInspector $inspector)
    {
    }

    public function id(): string
    {
        return 'laravel.fortify.two_factor_hardening';
    }

    public function name(): string
    {
        return 'Fortify two-factor management hardening';
    }

    public function category(): string
    {
        return 'authentication';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('fortify')) {
            return $this->skipped('Laravel Fortify is not installed.');
        }

        $features = array_values(array_filter(
            (array) $context->config('fortify.features', []),
            'is_string',
        ));

        if (!in_array(self::FEATURE, $features, true)) {
            return $this->skipped('Fortify two-factor authentication is not enabled.', [
                'version' => $context->capabilities->packageVersion('fortify'),
            ]);
        }

        $options = $context->config('fortify-options.' . self::FEATURE, []);
        $options = is_array($options) ? $options : [];
        $confirmEnrollment = ($options['confirm'] ?? false) === true;
        $confirmPassword = ($options['confirmPassword'] ?? false) === true;
        $routesChecked = 0;
        $missingAuthentication = [];
        $missingPasswordConfirmation = [];
        $resolutionFailures = 0;
        $limit = max(1, min(100, (int) $context->config('cybear.posture.max_evidence_items', 25)));

        foreach ($context->routes() as $route) {
            if (!$this->isManagementRoute($route)) {
                continue;
            }

            $routesChecked++;
            $inspection = $this->inspector->middleware($context, $route);
            $resolutionFailures += $inspection['resolution_failed'] ? 1 : 0;
            $middleware = $inspection['middleware'];

            if (!$inspection['resolution_failed']
                && !$this->inspector->hasAuthentication($middleware)
                && count($missingAuthentication) < $limit) {
                $missingAuthentication[] = $this->inspector->evidence($route);
            }

            if (!$inspection['resolution_failed']
                && $confirmPassword
                && !$this->inspector->hasPasswordConfirmation($middleware)
                && count($missingPasswordConfirmation) < $limit) {
                $missingPasswordConfirmation[] = $this->inspector->evidence($route);
            }
        }

        $evidence = [
            'version' => $context->capabilities->packageVersion('fortify'),
            'confirm_enrollment' => $confirmEnrollment,
            'confirm_password_for_management' => $confirmPassword,
            'management_routes_checked' => $routesChecked,
            'routes_missing_authentication' => $missingAuthentication,
            'routes_missing_password_confirmation' => $missingPasswordConfirmation,
            'middleware_resolution_failure_count' => $resolutionFailures,
        ];

        if ($routesChecked === 0) {
            return $this->warning(
                'Fortify two-factor authentication is enabled, but its management routes were not detected.',
                'If Fortify routes were intentionally replaced, verify the custom enrollment, disable, secret, and recovery-code endpoints require authentication and recent password confirmation.',
                $evidence,
                Severity::Medium,
            );
        }

        if ($missingAuthentication !== []) {
            return $this->fail(
                'Fortify two-factor management routes were found without verifiable authentication middleware.',
                'Restore Fortify authentication middleware on every two-factor enrollment, disable, secret, QR-code, and recovery-code route.',
                $evidence,
            );
        }

        if ($resolutionFailures > 0) {
            return $this->warning(
                'Some Fortify two-factor middleware could not be fully resolved.',
                'Resolve missing middleware aliases or classes and rerun the scan before relying on this authorization result.',
                $evidence,
            );
        }

        if (!$confirmEnrollment || !$confirmPassword || $missingPasswordConfirmation !== []) {
            return $this->warning(
                'Fortify two-factor authentication is enabled without all recommended enrollment and management confirmations.',
                'Enable both the confirm and confirmPassword options and retain password.confirm middleware on every two-factor management route.',
                $evidence,
                Severity::Medium,
            );
        }

        return $this->pass(
            'Fortify two-factor enrollment is confirmed and management routes require authentication plus password confirmation.',
            $evidence,
        );
    }

    private function isManagementRoute(Route $route): bool
    {
        $name = strtolower((string) ($route->getName() ?? ''));
        if (str_starts_with($name, 'two-factor.')
            && !in_array($name, ['two-factor.login', 'two-factor.login.store'], true)) {
            return true;
        }

        $action = strtolower($route->getActionName());

        return str_contains($action, 'laravel\\fortify\\http\\controllers\\')
            && (
                str_contains($action, 'twofactorauthenticationcontroller')
                || str_contains($action, 'confirmedtwofactorauthenticationcontroller')
                || str_contains($action, 'twofactorqrcodecontroller')
                || str_contains($action, 'twofactorsecretkeycontroller')
                || str_contains($action, 'recoverycodecontroller')
            );
    }
}
