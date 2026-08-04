<?php

namespace CybearCare\LaravelSecurity\Console\Commands;

use CybearCare\LaravelSecurity\Services\OpenApiSchemaGenerator;
use CybearCare\LaravelSecurity\Core\Api\CybearApiClient;
use Illuminate\Console\Command;

class ExportSchemaCommand extends Command
{
    protected $signature = 'cybear:export-schema
        {--output= : Write to file instead of stdout}
        {--format=json : Output format (json or yaml)}
        {--send : Send schema to Cybear Care SaaS}
        {--stats : Show route statistics only}';

    protected $description = 'Generate OpenAPI 3.0 schema from application routes';

    public function handle(OpenApiSchemaGenerator $generator): int
    {
        if ($this->option('stats')) {
            return $this->showStats($generator);
        }

        $this->info('Generating OpenAPI schema...');

        $schema = $generator->generate();
        $stats = $generator->getStatistics();

        $this->info("Processed {$stats['total_routes']} routes ({$stats['api_routes']} API, {$stats['web_routes']} web)");
        $this->info("{$stats['with_validation']} routes with validation rules extracted");
        $this->info("{$stats['auth_required']} routes requiring authentication");

        $format = $this->option('format');
        $output = $format === 'yaml' ? $generator->toYaml() : $generator->toJson();

        // Write to file
        $filePath = $this->option('output');
        if ($filePath) {
            file_put_contents($filePath, $output);
            $this->info("Schema written to {$filePath}");
        } else if (!$this->option('send')) {
            $this->line($output);
        }

        // Send to SaaS
        if ($this->option('send')) {
            return $this->sendToSaas($schema, $stats);
        }

        return 0;
    }

    protected function showStats(OpenApiSchemaGenerator $generator): int
    {
        $stats = $generator->getStatistics();

        $this->table(
            ['Metric', 'Count'],
            [
                ['Total Routes', $stats['total_routes']],
                ['API Routes', $stats['api_routes']],
                ['Web Routes', $stats['web_routes']],
                ['Auth Required', $stats['auth_required']],
                ['With Validation Rules', $stats['with_validation']],
            ]
        );

        $this->newLine();
        $this->info('HTTP Methods:');
        $this->table(
            ['Method', 'Count'],
            collect($stats['methods'])->map(fn($count, $method) => [$method, $count])->values()->toArray()
        );

        return 0;
    }

    protected function sendToSaas(array $schema, array $stats): int
    {
        $client = app(CybearApiClient::class);

        if (!$client->isConfigured()) {
            $this->error('Cybear API is not configured. Run php artisan cybear:setup first.');
            return 1;
        }

        $this->info('Sending schema to Cybear Care...');

        try {
            $client->sendCollectedData([
                'application_id' => config('cybear.app_id', config('app.name')),
                'collection_timestamp' => now()->format('Y-m-d\TH:i:s.u\Z'),
                'collectors' => [
                    'openapi_schema' => [
                        'schema' => $schema,
                        'statistics' => $stats,
                        'generated_at' => now()->toISOString(),
                    ],
                ],
            ]);

            $this->info('Schema sent successfully.');
            return 0;
        } catch (\Exception $e) {
            $this->error('Failed to send schema: ' . $e->getMessage());
            return 1;
        }
    }
}
