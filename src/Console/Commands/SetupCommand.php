<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use CybearCare\LaravelSecurity\Services\CybearApiClient;

class SetupCommand extends Command
{
    protected $signature = 'cybear:setup {--api-key= : Cybear API key}';
    protected $description = 'Set up Cybear Laravel Security package';

    public function handle()
    {
        $this->info('🛡️  Cybear Laravel Security Setup');
        $this->line('');

        // Check if already configured
        if ($this->isConfigured() && !$this->confirm('Cybear is already configured. Do you want to reconfigure?')) {
            return 0;
        }

        // Get API key
        $apiKey = $this->option('api-key') ?: $this->ask('Enter your Cybear API key');
        
        if (empty($apiKey)) {
            $this->error('API key is required');
            return 1;
        }

        // Setup progress
        $steps = [
            'Validating API key',
            'Updating environment file',
            'Publishing configuration',
            'Running database migrations',
            'Verifying domain ownership',
            'Syncing security rules'
        ];
        
        $progressBar = $this->output->createProgressBar(count($steps));
        $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage('Starting setup...');
        $progressBar->start();
        
        // Validate API key
        $progressBar->setMessage($steps[0]);
        if (!$this->validateApiKey($apiKey)) {
            $progressBar->finish();
            $this->line('');
            $this->error('Invalid API key or unable to connect to Cybear platform');
            return 1;
        }
        $progressBar->advance();

        // Update environment file
        $progressBar->setMessage($steps[1]);
        $this->updateEnvironmentFile($apiKey);
        $progressBar->advance();

        // Publish configuration
        $progressBar->setMessage($steps[2]);
        $this->callSilent('vendor:publish', [
            '--tag' => 'cybear-config',
            '--force' => true,
        ]);
        $progressBar->advance();

        // Run migrations
        $progressBar->setMessage($steps[3]);
        $this->callSilent('migrate');
        $progressBar->advance();

        // Auto-verify domain
        $progressBar->setMessage($steps[4]);
        $this->callSilent('cybear:verify-domain');
        $progressBar->advance();

        // Sync initial rules
        $progressBar->setMessage($steps[5]);
        $this->callSilent('cybear:sync');
        $progressBar->advance();
        
        $progressBar->setMessage('Setup completed');
        $progressBar->finish();
        $this->line('');
        $this->line('');

        $this->line('');
        $this->info('✅ Cybear Laravel Security has been successfully configured!');
        $this->line('');
        $this->line('Next steps:');
        $this->line('• Review your configuration in config/cybear.php');
        $this->line('• Run "php artisan cybear:status" to verify installation');
        $this->line('• Run "php artisan cybear:collect" to send initial data collection');

        return 0;
    }

    protected function isConfigured(): bool
    {
        return !empty(env('CYBEAR_API_KEY'));
    }

    protected function validateApiKey(string $apiKey): bool
    {
        try {
            $client = new CybearApiClient(
                env('CYBEAR_API_ENDPOINT', 'https://api.cybear.care'),
                $apiKey
            );

            return $client->authenticate();
        } catch (\Exception $e) {
            $this->warn('Connection test failed: ' . $e->getMessage());
            return false;
        }
    }

    protected function updateEnvironmentFile(string $apiKey): void
    {
        $envFile = base_path('.env');
        
        if (!File::exists($envFile)) {
            $this->warn('.env file not found, creating one...');
            File::put($envFile, '');
        }

        $envContent = File::get($envFile);
        
        $variables = [
            'CYBEAR_API_KEY' => $apiKey,
            'CYBEAR_API_ENDPOINT' => env('CYBEAR_API_ENDPOINT', 'https://api.cybear.care'),
            'CYBEAR_WAF_ENABLED' => 'true',
            'CYBEAR_WAF_MODE' => 'monitor',
            'CYBEAR_AUDIT_ENABLED' => 'true',
        ];

        foreach ($variables as $key => $value) {
            if (str_contains($envContent, $key . '=')) {
                // Update existing
                $envContent = preg_replace(
                    '/^' . preg_quote($key) . '=.*$/m',
                    $key . '=' . $value,
                    $envContent
                );
            } else {
                // Add new
                $envContent .= "\n{$key}={$value}";
            }
        }

        File::put($envFile, $envContent);
    }
}