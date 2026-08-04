<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use CybearCare\LaravelSecurity\Posture\CheckRegistry;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\CheckStatus;
use CybearCare\LaravelSecurity\Posture\PostureReport;
use CybearCare\LaravelSecurity\Posture\PostureRunner;
use CybearCare\LaravelSecurity\Posture\Severity;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use Illuminate\Console\Command;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;

final class ScanCommand extends Command
{
    protected $signature = 'cybear:scan
        {--format=table : Output format: table or json}
        {--output= : Write the complete JSON report to this file}
        {--force : Overwrite an existing output file}
        {--check=* : Run only these stable check IDs}
        {--category=* : Run only these check categories}
        {--minimum-severity=info : Lowest check severity to run}
        {--fail-on= : Exit with code 1 when a finding meets this severity}
        {--baseline= : Compare against a previous JSON report and gate only new occurrences}
        {--ci : Use deterministic CI gating with the configured severity threshold}
        {--send : Queue the report and attempt delivery to Cybear}';

    protected $description = 'Run Laravel-native security posture checks';

    public function __construct(
        private readonly PostureRunner $runner,
        private readonly CheckRegistry $registry,
        private readonly DataCollectionManager $collectionManager,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $jsonOutput = strtolower(trim((string) $this->option('format'))) === 'json';

        try {
            $format = $this->format();
            $ids = $this->stringListOption('check');
            $categories = $this->stringListOption('category');
            $minimum = Severity::parse((string) $this->option('minimum-severity'));
            $failOn = $this->option('fail-on');
            if ((bool) $this->option('ci') && (!is_string($failOn) || trim($failOn) === '')) {
                $failOn = (string) config('cybear.posture.ci_fail_on', 'high');
            }
            $failureThreshold = is_string($failOn) && $failOn !== ''
                ? Severity::parse($failOn)
                : null;
            $baselineFingerprints = $this->baselineFingerprints($this->option('baseline'));

            $this->validateSelection($ids, $categories);
            $report = $this->runner->run(
                $ids,
                $categories,
                $minimum,
                $baselineFingerprints,
            );
            if ($report->results === []) {
                throw new InvalidArgumentException('No posture checks matched the requested selection.');
            }

            $document = $report->jsonSerialize();

            if ((bool) $this->option('send')) {
                $document['delivery'] = $this->collectionManager->queuePostureReport($document);
            }

            $json = $this->encode($document);
            $outputPath = $this->option('output');
            if (is_string($outputPath) && trim($outputPath) !== '') {
                $writtenTo = $this->writeReport($outputPath, $json, (bool) $this->option('force'));
            }

            if ($format === 'json') {
                $this->output->writeln($json);
            } else {
                $this->renderTable($report, $document['delivery'] ?? null, $writtenTo ?? null);
            }

            if ($report->hasErrors()) {
                return self::INVALID;
            }

            if ($failureThreshold && $report->hasFindingAtOrAbove($failureThreshold)) {
                return self::FAILURE;
            }

            return self::SUCCESS;
        } catch (InvalidArgumentException|RuntimeException|JsonException $exception) {
            $this->renderError('invalid_scan', $exception->getMessage(), $jsonOutput);

            return self::INVALID;
        } catch (Throwable $exception) {
            report($exception);
            $this->renderError(
                'scan_failed',
                'The posture scan could not be completed. Review the application log.',
                $jsonOutput,
            );

            return self::FAILURE;
        }
    }

    private function format(): string
    {
        $format = strtolower(trim((string) $this->option('format')));

        if (!in_array($format, ['table', 'json'], true)) {
            throw new InvalidArgumentException('The --format option must be table or json.');
        }

        return $format;
    }

    /**
     * @return list<string>
     */
    private function stringListOption(string $name): array
    {
        return array_values(array_unique(array_filter(
            array_map(static fn (mixed $value): string => trim((string) $value), (array) $this->option($name)),
            static fn (string $value): bool => $value !== '',
        )));
    }

    /**
     * @param list<string> $ids
     * @param list<string> $categories
     */
    private function validateSelection(array $ids, array $categories): void
    {
        $unknownIds = array_values(array_diff($ids, $this->registry->ids()));
        if ($unknownIds !== []) {
            throw new InvalidArgumentException('Unknown check ID(s): ' . implode(', ', $unknownIds));
        }

        $unknownCategories = array_values(array_diff($categories, $this->registry->categories()));
        if ($unknownCategories !== []) {
            throw new InvalidArgumentException('Unknown check category/categories: ' . implode(', ', $unknownCategories));
        }

        $excluded = array_values(array_filter(
            (array) config('cybear.posture.excluded_checks', []),
            'is_string',
        ));
        $selectedButExcluded = array_values(array_intersect($ids, $excluded));
        if ($selectedButExcluded !== []) {
            throw new InvalidArgumentException(
                'Selected check ID(s) are excluded by configuration: ' . implode(', ', $selectedButExcluded),
            );
        }
    }

    /**
     * @param array<string, mixed> $document
     */
    private function encode(array $document): string
    {
        return json_encode(
            $document,
            JSON_PRETTY_PRINT
                | JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
                | JSON_INVALID_UTF8_SUBSTITUTE
                | JSON_THROW_ON_ERROR,
        );
    }

    private function writeReport(string $requestedPath, string $json, bool $force): string
    {
        $path = str_starts_with($requestedPath, DIRECTORY_SEPARATOR)
            ? $requestedPath
            : base_path($requestedPath);

        if (is_link($path)) {
            throw new RuntimeException('Refusing to write the report through a symbolic link.');
        }

        if (file_exists($path) && !$force) {
            throw new RuntimeException("Output file [{$requestedPath}] already exists. Use --force to overwrite it.");
        }

        if (file_exists($path) && !is_file($path)) {
            throw new RuntimeException("Output path [{$requestedPath}] is not a regular file.");
        }

        $directory = dirname($path);
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new RuntimeException("Output directory [{$directory}] does not exist or is not writable.");
        }

        $temporary = tempnam($directory, '.cybear-posture-');
        if ($temporary === false) {
            throw new RuntimeException('Could not create a temporary report file.');
        }

        try {
            @chmod($temporary, 0600);
            if (file_put_contents($temporary, $json . PHP_EOL, LOCK_EX) === false) {
                throw new RuntimeException('Could not write the posture report.');
            }

            if (!rename($temporary, $path)) {
                throw new RuntimeException('Could not move the posture report into place.');
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }

        return $path;
    }

    /**
     * @return list<string>
     */
    private function baselineFingerprints(mixed $requestedPath): array
    {
        if (!is_string($requestedPath) || trim($requestedPath) === '') {
            return [];
        }

        $path = str_starts_with($requestedPath, DIRECTORY_SEPARATOR)
            ? $requestedPath
            : base_path($requestedPath);

        if (is_link($path) || !is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException(
                "Baseline [{$requestedPath}] must be a readable regular file and may not be a symbolic link.",
            );
        }

        $size = filesize($path);
        if (!is_int($size) || $size < 1 || $size > 10 * 1024 * 1024) {
            throw new InvalidArgumentException('The baseline must be between 1 byte and 10 MiB.');
        }

        $contents = file_get_contents($path);
        if (!is_string($contents)) {
            throw new InvalidArgumentException("Baseline [{$requestedPath}] could not be read.");
        }

        $document = json_decode($contents, true, 64, JSON_THROW_ON_ERROR);
        if (!is_array($document) || !is_array($document['results'] ?? null)) {
            throw new InvalidArgumentException('The baseline is not a Cybear posture report.');
        }

        $fingerprints = [];
        foreach ($document['results'] as $result) {
            if (!is_array($result)) {
                continue;
            }

            $occurrences = array_values(array_filter(
                (array) ($result['occurrences'] ?? []),
                'is_array',
            ));
            foreach ($occurrences as $occurrence) {
                $fingerprints[] = $occurrence['fingerprint'] ?? null;
            }

            if ($occurrences === []
                && in_array($result['status'] ?? null, ['warning', 'fail', 'suppressed'], true)) {
                $fingerprints[] = $result['fingerprint'] ?? null;
            }
        }

        $fingerprints = array_values(array_unique(array_filter(
            $fingerprints,
            static fn (mixed $fingerprint): bool =>
                is_string($fingerprint)
                && preg_match('/^[a-f0-9]{64}$/', $fingerprint) === 1,
        )));

        return $fingerprints;
    }

    /**
     * @param array{queued: true, transmitted: bool, record_id: int}|null $delivery
     */
    private function renderTable(PostureReport $report, ?array $delivery, ?string $writtenTo): void
    {
        $this->components->info('Laravel security posture');
        $packages = array_keys((array) ($report->capabilities['packages'] ?? []));
        $runtime = (array) ($report->capabilities['runtime'] ?? []);
        $this->line('Detected packages: ' . ($packages !== [] ? implode(', ', $packages) : 'none'));
        $this->line(sprintf(
            'Runtime: cache=%s  queue=%s  session=%s  database=%s',
            $runtime['cache_driver'] ?? 'unknown',
            $runtime['queue_driver'] ?? 'unknown',
            $runtime['session_driver'] ?? 'unknown',
            $runtime['database_driver'] ?? 'unknown',
        ));
        $this->newLine();
        $this->table(
            ['Status', 'Severity', 'Check', 'Summary'],
            array_map(
                fn (CheckResult $result): array => [
                    $this->statusLabel($result->status),
                    strtoupper($result->severity->value),
                    $result->name,
                    $result->summary,
                ],
                $report->results,
            ),
        );

        $summary = $report->summary();
        $this->line(sprintf(
            'Checks: %d  Pass: %d  Findings: %d  Suppressed: %d  Skipped: %d  Errors: %d',
            $summary['checks'],
            $summary['statuses']['pass'],
            $summary['statuses']['warning'] + $summary['statuses']['fail'],
            $summary['statuses']['suppressed'],
            $summary['statuses']['skipped'],
            $summary['statuses']['error'],
        ));

        $findings = array_filter(
            $report->results,
            static fn (CheckResult $result): bool => $result->status->isFinding(),
        );

        foreach ($findings as $finding) {
            $this->newLine();
            $this->components->warn("{$finding->name}: {$finding->summary}");
            if ($finding->remediation) {
                $this->line('  Fix: ' . $finding->remediation);
            }
            foreach (array_slice($finding->occurrences, 0, 5) as $occurrence) {
                $evidence = $occurrence->evidence;
                $method = implode('|', (array) ($evidence['methods'] ?? []));
                $target = trim($method . ' /' . ltrim((string) ($evidence['uri'] ?? ''), '/'));
                $location = (array) ($evidence['location'] ?? []);
                $source = isset($location['file'], $location['line'])
                    ? " ({$location['file']}:{$location['line']})"
                    : '';
                $this->line("  Affected: {$target}{$source}");
            }
        }

        if ($delivery !== null) {
            $this->newLine();
            $delivery['transmitted']
                ? $this->components->info('The report was queued and acknowledged by Cybear.')
                : $this->components->warn('The report is safely queued locally and will be retried.');
        }

        if ($writtenTo !== null) {
            $this->components->info("JSON report written to {$writtenTo}");
        }
    }

    private function statusLabel(CheckStatus $status): string
    {
        return match ($status) {
            CheckStatus::Pass => '<fg=green>PASS</>',
            CheckStatus::Warning => '<fg=yellow>WARN</>',
            CheckStatus::Fail => '<fg=red>FAIL</>',
            CheckStatus::Suppressed => '<fg=gray>SUPPRESSED</>',
            CheckStatus::Skipped => '<fg=gray>SKIP</>',
            CheckStatus::Error => '<fg=red>ERROR</>',
        };
    }

    private function renderError(string $type, string $message, bool $json): void
    {
        if (!$json) {
            $this->components->error($message);

            return;
        }

        $this->output->writeln((string) json_encode([
            'schema_version' => PostureReport::SCHEMA_VERSION,
            'error' => [
                'type' => $type,
                'message' => $message,
            ],
        ], JSON_PRETTY_PRINT
            | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
            | JSON_INVALID_UTF8_SUBSTITUTE));
    }
}
