<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use CybearCare\LaravelSecurity\Core\Collection\DataCollectionManager as CoreDataCollectionManager;
use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Waf\WafEngine;
use CybearCare\LaravelSecurity\Services\DataCollectionManager;
use CybearCare\LaravelSecurity\Services\DomainVerificationService;
use CybearCare\LaravelSecurity\Services\SyncOrchestrator;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Throwable;

class SetupCommand extends Command
{
    protected $signature = 'cybear:setup
        {--api-key= : Cybear API key}
        {--force : Replace an already-published Cybear config file}';

    protected $description = 'Set up Cybear Laravel Security';

    public function handle(): int
    {
        $this->info('Cybear Laravel Security setup');

        if ($this->isConfigured() && !$this->confirm('Cybear is already configured. Reconfigure it?')) {
            return self::SUCCESS;
        }

        $apiKey = trim((string) ($this->option('api-key') ?: $this->secret('Enter your Cybear API key')));
        if ($apiKey === '' || preg_match('/[\r\n]/', $apiKey)) {
            $this->error('A valid API key is required.');

            return self::FAILURE;
        }

        if (!File::isFile(base_path('.env'))) {
            $this->error('No .env file exists. Create the application environment file before running setup.');

            return self::FAILURE;
        }

        if ((string) config('app.key', '') === '') {
            $this->error('APP_KEY is required because local Cybear telemetry is encrypted.');

            return self::FAILURE;
        }

        if (!filter_var((string) config('app.url'), FILTER_VALIDATE_URL)) {
            $this->error('APP_URL must be a valid absolute URL before domain verification can run.');

            return self::FAILURE;
        }

        if (!$this->updateEnvironmentFile([
            'CYBEAR_ENABLED' => 'false',
            'CYBEAR_API_KEY' => $apiKey,
            'CYBEAR_API_ENDPOINT' => (string) config('cybear.api.endpoint', 'https://api.cybear.care'),
            'CYBEAR_WAF_ENABLED' => 'true',
            'CYBEAR_WAF_MODE' => 'monitor',
            'CYBEAR_AUDIT_ENABLED' => 'true',
            'CYBEAR_AUDIT_LOG_REQUESTS' => 'true',
        ])) {
            return self::FAILURE;
        }

        config([
            'cybear.enabled' => false,
            'cybear.api.key' => $apiKey,
        ]);
        $this->refreshRuntimeBindings();

        if (!$this->validateApiKey()) {
            $this->error('The API key could not be authenticated. Cybear remains disabled.');

            return self::FAILURE;
        }

        $publishArguments = ['--tag' => 'cybear-config'];
        if ($this->option('force')) {
            $publishArguments['--force'] = true;
        }

        if (!$this->runRequiredCommand('vendor:publish', $publishArguments, 'publishing configuration')
            || !$this->runRequiredCommand('migrate', ['--force' => true], 'running migrations')
            || !$this->verifyDomain()
            || !$this->syncRules()) {
            $this->error('Setup stopped. CYBEAR_ENABLED remains false, so the HTTP pipeline is unchanged.');

            return self::FAILURE;
        }

        if (!$this->updateEnvironmentFile(['CYBEAR_ENABLED' => 'true'])) {
            $this->error('Setup completed, but the package could not be enabled in .env.');

            return self::FAILURE;
        }

        config(['cybear.enabled' => true]);

        $this->newLine();
        $this->info('Cybear is configured in monitor mode.');
        $this->line('Review config/cybear.php, then run php artisan cybear:status.');

        return self::SUCCESS;
    }

    protected function isConfigured(): bool
    {
        return (string) config('cybear.api.key', '') !== '';
    }

    protected function validateApiKey(): bool
    {
        try {
            return app(CybearApiClient::class)->authenticate();
        } catch (Throwable $exception) {
            $this->warn('Connection test failed: ' . $exception->getMessage());

            return false;
        }
    }

    protected function refreshRuntimeBindings(): void
    {
        foreach ([
            CybearConfig::class,
            CybearApiClient::class,
            DomainVerificationService::class,
            DataCollectionManager::class,
            CoreDataCollectionManager::class,
            WafEngine::class,
            SyncOrchestrator::class,
        ] as $abstract) {
            app()->forgetInstance($abstract);
        }
    }

    protected function runRequiredCommand(string $command, array $arguments, string $description): bool
    {
        $this->line(ucfirst($description) . '...');
        $exitCode = $this->call($command, $arguments);

        if ($exitCode !== self::SUCCESS) {
            $this->error("Failed while {$description} (exit code {$exitCode}).");

            return false;
        }

        return true;
    }

    protected function verifyDomain(): bool
    {
        $this->line('Verifying domain ownership...');
        $result = app(DomainVerificationService::class)->autoVerify();

        if (!($result['success'] ?? false)) {
            $this->error($result['message'] ?? 'Domain verification failed.');

            return false;
        }

        return true;
    }

    protected function syncRules(): bool
    {
        $this->line('Synchronizing WAF rules...');

        try {
            $count = app(WafEngine::class)->syncRules();
            $this->line("Synchronized {$count} WAF rule(s).");

            return true;
        } catch (Throwable $exception) {
            $this->error('WAF rule synchronization failed: ' . $exception->getMessage());

            return false;
        }
    }

    /**
     * @param array<string, string> $variables
     */
    protected function updateEnvironmentFile(array $variables): bool
    {
        $path = base_path('.env');

        try {
            $content = (string) File::get($path);
            $permissions = fileperms($path);

            foreach ($variables as $key => $value) {
                $line = $key . '=' . $this->quoteEnvironmentValue($value);
                $pattern = '/^' . preg_quote($key, '/') . '=.*$/m';

                if (preg_match($pattern, $content)) {
                    $content = (string) preg_replace($pattern, $line, $content, 1);
                } else {
                    $content = rtrim($content) . PHP_EOL . $line . PHP_EOL;
                }
            }

            $temporary = $path . '.cybear-' . bin2hex(random_bytes(6));
            if (File::put($temporary, $content) === false) {
                throw new \RuntimeException('Unable to write the temporary environment file.');
            }
            if ($permissions !== false) {
                @chmod($temporary, $permissions & 0777);
            }
            if (!File::move($temporary, $path)) {
                File::delete($temporary);
                throw new \RuntimeException('Atomic environment-file replacement failed.');
            }

            return true;
        } catch (Throwable $exception) {
            $this->error('Unable to update .env: ' . $exception->getMessage());

            return false;
        }
    }

    protected function quoteEnvironmentValue(string $value): string
    {
        return '"' . str_replace(
            ['\\', '"', '$'],
            ['\\\\', '\\"', '\\$'],
            $value,
        ) . '"';
    }
}
