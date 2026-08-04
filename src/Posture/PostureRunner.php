<?php

namespace CybearCare\LaravelSecurity\Posture;

use Composer\InstalledVersions;
use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use Throwable;

final readonly class PostureRunner
{
    public function __construct(
        private CheckRegistry $registry,
        private CheckContext $context,
        private LoggerInterface $logger,
        private FindingSuppressor $suppressor,
    ) {
    }

    /**
     * @param list<string> $ids
     * @param list<string> $categories
     * @param list<string> $baselineFingerprints
     */
    public function run(
        array $ids = [],
        array $categories = [],
        Severity $minimumSeverity = Severity::Info,
        array $baselineFingerprints = [],
    ): PostureReport {
        $startedAt = new DateTimeImmutable();
        $results = [];
        $excluded = array_values(array_filter(
            (array) $this->context->config('cybear.posture.excluded_checks', []),
            'is_string',
        ));
        $checks = $this->registry->select($ids, $categories, $minimumSeverity, $excluded);

        foreach ($checks as $check) {
            $started = hrtime(true);

            try {
                $result = $check->run($this->context);
                $duration = (hrtime(true) - $started) / 1_000_000;
                $results[] = $this->suppressor->apply(
                    $result->withDuration($duration),
                    array_values(array_filter(
                        (array) $this->context->config('cybear.posture.suppressions', []),
                        'is_array',
                    )),
                    $baselineFingerprints,
                );
            } catch (Throwable $exception) {
                $duration = (hrtime(true) - $started) / 1_000_000;
                $results[] = CheckResult::error($check, $duration);
                $this->logger->error('A Cybear posture check failed unexpectedly', [
                    'check_id' => $check->id(),
                    'exception' => $exception::class,
                    'error' => $exception->getMessage(),
                ]);
            }
        }

        return new PostureReport(
            startedAt: $startedAt,
            completedAt: new DateTimeImmutable(),
            application: $this->applicationMetadata(),
            capabilities: $this->context->capabilities->jsonSerialize(),
            results: $results,
            selection: [
                'check_ids' => $ids,
                'categories' => $categories,
                'minimum_severity' => $minimumSeverity->value,
                'excluded_check_ids' => $excluded,
                'baseline_fingerprint_count' => count($baselineFingerprints),
            ],
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function applicationMetadata(): array
    {
        $appUrl = (string) $this->context->config('app.url', '');
        $host = parse_url($appUrl, PHP_URL_HOST);

        return [
            'application_id' => (string) (
                $this->context->config('cybear.app_id')
                ?: $this->context->config('app.name', 'laravel')
            ),
            'deployment_id' => $this->context->config('cybear.deployment_id'),
            'environment' => $this->context->environment(),
            'host' => is_string($host) ? strtolower($host) : null,
            'laravel_version' => $this->context->application->version(),
            'php_version' => PHP_VERSION,
            'package_version' => $this->packageVersion(),
        ];
    }

    private function packageVersion(): string
    {
        try {
            if (class_exists(InstalledVersions::class)
                && InstalledVersions::isInstalled('cybear-care/laravel-security')) {
                return InstalledVersions::getPrettyVersion('cybear-care/laravel-security') ?? 'dev';
            }
        } catch (Throwable) {

        }

        return 'dev';
    }
}
