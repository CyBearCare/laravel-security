<?php

namespace CybearCare\LaravelSecurity\Core\Api;

use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;

class CybearApiClient
{
    protected string $endpoint;

    protected string $apiKey;

    protected int $timeout;

    protected int $retryAttempts;

    protected int $retryDelay;

    public function __construct(
        protected CybearConfig $config,
        protected LoggerInterface $logger,
        protected CacheInterface $cache,
    ) {
        $this->endpoint = rtrim($config->getApiEndpoint(), '/');
        $this->apiKey = $config->getApiKey() ?? '';
        $this->timeout = max(1, $config->getApiTimeout());
        $this->retryAttempts = max(1, $config->getApiRetryAttempts());
        $this->retryDelay = max(0, $config->getApiRetryDelay());
    }

    public function isConfigured(): bool
    {
        return $this->apiKey !== '' && $this->endpoint !== '';
    }

    public function authenticate(): bool
    {
        if (! $this->isConfigured()) {
            return false;
        }

        try {
            return (bool) ($this->makeRequest('GET', '/api/laravel/auth/verify')['success'] ?? false);
        } catch (Throwable $exception) {
            $this->logger->error('Cybear API authentication failed', [
                'error' => $exception->getMessage(),
                'endpoint' => $this->endpoint,
            ]);

            return false;
        }
    }

    public function verifyAuth(): array
    {
        return $this->makeRequest('GET', '/api/laravel/auth/verify');
    }

    public function sendCollectedData(array $data): array
    {
        return $this->makeRequest(
            'POST',
            '/api/laravel/data/collect',
            $data,
            isset($data['outbox_id']) ? (string) $data['outbox_id'] : null,
        );
    }

    public function syncRules(): array
    {
        $lastSync = $this->cache->get('cybear_rules_last_sync');

        return $this->makeRequest(
            'GET',
            '/api/laravel/rules/sync',
            $lastSync ? ['since' => $lastSync] : [],
        );
    }

    public function getHealthStatus(): array
    {
        return $this->makeRequest('GET', '/api/laravel/health');
    }

    public function sendAuditLogs(array $logs, ?string $idempotencyKey = null): array|false
    {
        return $this->sendBatch('/api/laravel/audit/submit', 'logs', $logs, $idempotencyKey);
    }

    public function sendBlockedRequests(array $blockedRequests, ?string $idempotencyKey = null): array|false
    {
        return $this->sendBatch(
            '/api/laravel/blocked/submit',
            'blocked_requests',
            $blockedRequests,
            $idempotencyKey,
        );
    }

    public function initOrActivate(string $appUrl, string $appName, string $frameworkVersion): array
    {
        return $this->makeRequest('POST', '/api/laravel/init-or-activate', [
            'app_url' => $appUrl,
            'app_name' => $appName,
            'laravel_version' => $frameworkVersion,
            'php_version' => PHP_VERSION,
        ]);
    }

    public function verify(string $appUrl): array
    {
        return $this->makeRequest('POST', '/api/laravel/verify', ['app_url' => $appUrl]);
    }

    public function testConnection(): array
    {
        try {
            $startedAt = microtime(true);
            $response = $this->getHealthStatus();

            return [
                'success' => true,
                'response_time' => round((microtime(true) - $startedAt) * 1000, 2),
                'response' => $response,
            ];
        } catch (Throwable $exception) {
            return ['success' => false, 'error' => $exception->getMessage()];
        }
    }

    protected function sendBatch(
        string $endpoint,
        string $key,
        array $records,
        ?string $idempotencyKey = null,
    ): array|false {
        try {
            $response = $this->makeRequest('POST', $endpoint, [$key => $records], $idempotencyKey);

            $result = is_array($response['data'] ?? null) ? $response['data'] : $response;
            if (array_key_exists('success', $response)) {
                $result['success'] = $response['success'];
            }

            return $result;
        } catch (Throwable $exception) {
            $this->logger->error('Failed to send a Cybear telemetry batch', [
                'endpoint' => $endpoint,
                'records_count' => count($records),
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    protected function makeRequest(
        string $method,
        string $path,
        array $data = [],
        ?string $idempotencyKey = null,
    ): array {
        if (! $this->isConfigured()) {
            throw new RuntimeException('Cybear is not configured. Set CYBEAR_API_KEY and CYBEAR_API_ENDPOINT.');
        }

        $attempt = 0;

        while (++$attempt <= $this->retryAttempts) {
            try {
                $response = $this->request($idempotencyKey)
                    ->send(strtoupper($method), ltrim($path, '/'), $this->options($method, $data));

                if ($response->successful()) {
                    return $this->decodeResponse($response);
                }

                if ($response->clientError() || $attempt >= $this->retryAttempts) {
                    throw new RuntimeException($this->failureMessage($response, $path));
                }
            } catch (ConnectionException $exception) {
                if ($attempt >= $this->retryAttempts) {
                    throw new RuntimeException(
                        "Unable to connect to the Cybear API after {$attempt} attempt(s).",
                        previous: $exception,
                    );
                }
            }

            if ($this->retryDelay > 0) {
                usleep($this->retryDelay * 1000 * $attempt);
            }
        }

        throw new RuntimeException('Unexpected Cybear API request failure.');
    }

    protected function request(?string $idempotencyKey = null): PendingRequest
    {
        $request = Http::baseUrl($this->endpoint)
            ->acceptJson()
            ->asJson()
            ->withHeaders([
                'X-Cybear-API-Key' => $this->apiKey,
                'User-Agent' => 'Cybear-Laravel/'.$this->getPackageVersion(),
            ])
            ->timeout($this->timeout)
            ->connectTimeout(min($this->timeout, 10))
            ->withoutRedirecting();

        return $idempotencyKey
            ? $request->withHeader('Idempotency-Key', $idempotencyKey)
            : $request;
    }

    protected function options(string $method, array $data): array
    {
        if ($data === []) {
            return [];
        }

        return strtoupper($method) === 'GET' ? ['query' => $data] : ['json' => $data];
    }

    protected function decodeResponse(Response $response): array
    {
        $payload = $response->json();

        if (! is_array($payload)) {
            throw new RuntimeException('Cybear API returned an invalid JSON response.');
        }

        return $payload;
    }

    protected function failureMessage(Response $response, string $path): string
    {
        $message = $response->json('message');

        return sprintf(
            'Cybear API request to %s failed with HTTP %d%s.',
            $path,
            $response->status(),
            is_string($message) && $message !== '' ? ': '.$message : '',
        );
    }

    protected function getPackageVersion(): string
    {
        $composerFile = dirname(__DIR__, 3).'/composer.json';

        if (! is_file($composerFile)) {
            return 'dev';
        }

        $composer = json_decode((string) file_get_contents($composerFile), true);

        return is_array($composer) ? ($composer['version'] ?? 'dev') : 'dev';
    }
}
