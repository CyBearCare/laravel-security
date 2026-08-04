<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;

final class OctaneRuntimeSafetyCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.octane.runtime_safety';
    }

    public function name(): string
    {
        return 'Octane long-lived worker safety';
    }

    public function category(): string
    {
        return 'runtime';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function confidence(): Confidence
    {
        return Confidence::Medium;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (!$context->capabilities->hasPackage('octane')) {
            return $this->skipped('Laravel Octane is not installed.');
        }

        $maximumExecution = $context->config('octane.max_execution_time', 30);
        $garbageThreshold = $context->config('octane.garbage', 50);
        $listeners = $context->config('octane.listeners', []);
        $listeners = is_array($listeners) ? $listeners : [];
        $required = [
            'request_reset' => [
                'event' => 'Laravel\\Octane\\Events\\RequestReceived',
                'suffixes' => ['FlushTemporaryContainerInstances'],
            ],
            'operation_cleanup' => [
                'event' => 'Laravel\\Octane\\Contracts\\OperationTerminated',
                'suffixes' => ['FlushOnce', 'FlushTemporaryContainerInstances'],
            ],
            'worker_error_stop' => [
                'event' => 'Laravel\\Octane\\Events\\WorkerErrorOccurred',
                'suffixes' => ['StopWorkerIfNecessary'],
            ],
        ];
        $listenerStatus = [];
        $missing = [];

        foreach ($required as $name => $definition) {
            $configured = $listeners[$definition['event']] ?? [];
            $configured = is_array($configured) ? $configured : [];
            $present = [];

            foreach ($definition['suffixes'] as $suffix) {
                $found = $this->containsListener($configured, $suffix);
                $present[$suffix] = $found;
                if (!$found) {
                    $missing[] = "{$name}:{$suffix}";
                }
            }

            $listenerStatus[$name] = $present;
        }

        $executionSeconds = is_numeric($maximumExecution) ? (int) $maximumExecution : null;
        $garbageMegabytes = is_numeric($garbageThreshold) ? (int) $garbageThreshold : null;
        $evidence = [
            'version' => $context->capabilities->packageVersion('octane'),
            'server' => is_string($context->config('octane.server'))
                ? substr((string) $context->config('octane.server'), 0, 50)
                : null,
            'max_execution_time_seconds' => $executionSeconds,
            'garbage_collection_megabytes' => $garbageMegabytes,
            'required_listener_status' => $listenerStatus,
            'missing_lifecycle_listeners' => $missing,
            'scanner_scope' => 'configuration and framework reset listeners; application singleton state requires code review',
        ];

        if ($missing !== []) {
            return $this->fail(
                'Octane lifecycle reset or worker-failure listeners are missing from the effective configuration.',
                'Restore Octane default request reset, operation cleanup, and worker error listeners before serving untrusted traffic with long-lived workers.',
                $evidence,
                Severity::High,
            );
        }

        if ($executionSeconds === null || $executionSeconds <= 0
            || $garbageMegabytes === null || $garbageMegabytes <= 0) {
            return $this->warning(
                'Octane has an unbounded request execution time or disabled garbage-collection threshold.',
                'Set a positive max_execution_time and garbage threshold appropriate to the application, and separately review application singletons for captured request, container, or mutable user state.',
                $evidence,
            );
        }

        return $this->pass(
            'Octane has bounded execution and its core long-lived worker reset listeners are present.',
            $evidence,
        );
    }

    /**
     * @param array<int, mixed> $listeners
     */
    private function containsListener(array $listeners, string $suffix): bool
    {
        foreach ($listeners as $listener) {
            if (is_string($listener)
                && ($listener === $suffix || str_ends_with($listener, '\\' . $suffix))) {
                return true;
            }
        }

        return false;
    }
}
