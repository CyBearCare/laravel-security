<?php

namespace CybearCare\LaravelSecurity\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ConnectException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class CybearApiClient
{
    protected Client $httpClient;
    protected string $endpoint;
    protected string $apiKey;
    protected int $timeout;
    protected int $retryAttempts;
    protected int $retryDelay;

    public function __construct(string $endpoint, ?string $apiKey = null, int $timeout = 30)
    {
        $this->endpoint = rtrim($endpoint, '/');
        $this->apiKey = $apiKey ?? '';
        $this->timeout = $timeout;
        $this->retryAttempts = config('cybear.api.retry_attempts', 3);
        $this->retryDelay = config('cybear.api.retry_delay', 1000);

        $this->httpClient = new Client([
            'timeout' => $this->timeout,
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'Cybear-Laravel/' . $this->getPackageVersion(),
                'X-Cybear-API-Key' => $this->apiKey,
            ],
            // Enforce SSL/TLS certificate verification
            'verify' => true,
            // Additional security options
            'allow_redirects' => [
                'max' => 5,
                'strict' => true,
                'referer' => true,
                'protocols' => ['https'],
            ],
            'http_errors' => true,
        ]);
    }

    public function isConfigured(): bool
    {
        return !empty($this->apiKey) && !empty($this->endpoint);
    }

    public function authenticate(): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        try {
            $response = $this->makeRequest('GET', '/api/laravel/auth/verify');
            return $response['success'] ?? false;
        } catch (\Exception $e) {
            Log::error('Cybear API authentication failed', [
                'error' => $e->getMessage(),
                'endpoint' => $this->endpoint
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
        return $this->makeRequest('POST', '/api/laravel/data/collect', $data);
    }

    public function syncRules(): array
    {
        $cacheKey = 'cybear_rules_last_sync';
        $lastSync = Cache::get($cacheKey);
        
        $params = [];
        if ($lastSync) {
            $params['since'] = $lastSync;
        }

        $response = $this->makeRequest('GET', '/api/laravel/rules/sync', $params);
        
        if (!empty($response['data']['rules'])) {
            Cache::put($cacheKey, now()->toISOString(), 3600);
        }

        return $response;
    }


    public function getHealthStatus(): array
    {
        return $this->makeRequest('GET', '/api/laravel/health');
    }

    public function receiveConfigUpdates(): array
    {
        return $this->makeRequest('GET', '/config/updates', [
            'application_id' => config('cybear.app_id', config('app.name')),
        ]);
    }

    public function sendAuditLogs(array $logs): bool
    {
        try {
            $this->makeRequest('POST', '/api/laravel/audit/submit', [
                'logs' => $logs,
            ]);
            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send audit logs to Cybear', [
                'error' => $e->getMessage(),
                'logs_count' => count($logs)
            ]);
            return false;
        }
    }

    public function sendBlockedRequests(array $blockedRequests): bool
    {
        try {
            $this->makeRequest('POST', '/api/laravel/blocked/submit', [
                'blocked_requests' => $blockedRequests,
            ]);
            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send blocked requests to Cybear', [
                'error' => $e->getMessage(),
                'requests_count' => count($blockedRequests)
            ]);
            return false;
        }
    }

    public function initOrActivate(): array
    {
        try {
            return $this->makeRequest('POST', '/api/laravel/init-or-activate', [
                'app_url' => config('app.url'),
                'app_name' => config('app.name'),
                'laravel_version' => app()->version(),
                'php_version' => PHP_VERSION,
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to initialize/activate Cybear', [
                'error' => $e->getMessage()
            ]);
            throw $e;
        }
    }

    public function verify(): array
    {
        try {
            return $this->makeRequest('POST', '/api/laravel/verify', [
                'app_url' => config('app.url'),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to verify Cybear', [
                'error' => $e->getMessage()
            ]);
            throw $e;
        }
    }

    public function reportSecurityIncident(array $incident): array
    {
        return $this->makeRequest('POST', '/incidents/report', [
            'incident' => $incident,
            'timestamp' => now()->toISOString(),
            'application_id' => config('cybear.app_id', config('app.name')),
        ]);
    }

    protected function makeRequest(string $method, string $endpoint, array $data = []): array
    {
        $url = $this->endpoint . $endpoint;
        $attempt = 0;

        while ($attempt < $this->retryAttempts) {
            try {
                $options = [];
                
                if (!empty($data)) {
                    if ($method === 'GET') {
                        $options['query'] = $data;
                    } else {
                        $options['json'] = $data;
                    }
                }

                $response = $this->httpClient->request($method, $url, $options);
                $responseData = json_decode($response->getBody()->getContents(), true);

                Log::debug('Cybear API request successful', [
                    'method' => $method,
                    'endpoint' => $endpoint,
                    'status_code' => $response->getStatusCode(),
                    'attempt' => $attempt + 1
                ]);

                return $responseData ?? [];

            } catch (ConnectException $e) {
                $attempt++;
                
                if ($attempt >= $this->retryAttempts) {
                    throw new \Exception("Unable to connect to Cybear API after {$this->retryAttempts} attempts: " . $e->getMessage());
                }

                usleep($this->retryDelay * 1000 * $attempt); // Exponential backoff
                
            } catch (RequestException $e) {
                $statusCode = $e->getResponse() ? $e->getResponse()->getStatusCode() : 0;
                
                // Don't retry on client errors (4xx)
                if ($statusCode >= 400 && $statusCode < 500) {
                    throw new \Exception("Cybear API client error: " . $e->getMessage());
                }

                $attempt++;
                
                if ($attempt >= $this->retryAttempts) {
                    throw new \Exception("Cybear API request failed after {$this->retryAttempts} attempts: " . $e->getMessage());
                }

                usleep($this->retryDelay * 1000 * $attempt); // Exponential backoff
            }
        }

        throw new \Exception("Unexpected error in API request");
    }

    protected function compressData(array $data): string
    {
        $jsonData = json_encode($data);
        
        if (config('cybear.collectors.compression', true) && function_exists('gzencode')) {
            return base64_encode(gzencode($jsonData, 6));
        }

        return base64_encode($jsonData);
    }

    protected function getPackageVersion(): string
    {
        try {
            // Try to read from our own composer.json
            $composerFile = __DIR__ . '/../../composer.json';
            if (file_exists($composerFile)) {
                $composer = json_decode(file_get_contents($composerFile), true);
                return $composer['version'] ?? '1.0.0';
            }
        } catch (\Exception $e) {
            // Ignore errors
        }
        
        // Fallback to static version
        return '1.0.0';
    }

    public function testConnection(): array
    {
        try {
            $startTime = microtime(true);
            $response = $this->getHealthStatus();
            $endTime = microtime(true);

            return [
                'success' => true,
                'response_time' => round(($endTime - $startTime) * 1000, 2),
                'response' => $response,
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}