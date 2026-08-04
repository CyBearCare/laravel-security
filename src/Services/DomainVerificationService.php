<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class DomainVerificationService
{
    protected \CybearCare\LaravelSecurity\Core\Api\CybearApiClient $apiClient;

    public function __construct(\CybearCare\LaravelSecurity\Core\Api\CybearApiClient $apiClient)
    {
        $this->apiClient = $apiClient;
    }

    public function autoVerify(): array
    {
        $key = 'cybear-verify:' . hash('sha256', (string) config('app.url'));
        $verificationHash = null;
        
        if (!RateLimiter::attempt($key, 5, function() {}, 60)) {
            Log::warning('Domain verification rate limit exceeded');
            
            return [
                'success' => false,
                'message' => 'Too many verification attempts. Please try again later.'
            ];
        }
        
        try {
            $response = $this->apiClient->initOrActivate(
                config('app.url'),
                config('app.name'),
                app()->version()
            );
            
            if (!($response['success'] ?? false)) {
                return [
                    'success' => false,
                    'message' => 'Failed to initialize: ' . ($response['message'] ?? 'Unknown error')
                ];
            }

            $data = $response['data'] ?? [];

            if ($data['is_activated'] ?? false) {
                Cache::put('cybear_domain_verified', true, 300);

                return [
                    'success' => true,
                    'message' => 'Domain is already verified and activated',
                    'status' => 'activated'
                ];
            }

            if (($data['next_step'] ?? '') === 'verify') {
                $verificationHash = $data['verification_hash'] ?? null;

                if (!is_string($verificationHash)) {
                    return [
                        'success' => false,
                        'message' => 'The verification response did not contain a valid token',
                    ];
                }
                
                Log::info('Domain verification required', [
                    'url' => $data['verification_url'] ?? null
                ]);

                if (!$this->createVerificationFile($verificationHash)) {
                    return [
                        'success' => false,
                        'message' => 'Failed to create verification file'
                    ];
                }

                $verifyResponse = $this->apiClient->verify(config('app.url'));
                
                if (!($verifyResponse['success'] ?? false)) {
                    return [
                        'success' => false,
                        'message' => 'Domain verification failed: ' . ($verifyResponse['message'] ?? 'Unknown error')
                    ];
                }

                Cache::put('cybear_domain_verified', true, 300);

                return [
                    'success' => true,
                    'message' => 'Domain verified and activated successfully',
                    'status' => 'verified'
                ];
            }

            return [
                'success' => false,
                'message' => 'Unknown verification state'
            ];

        } catch (\Throwable $e) {
            Log::error('Auto verification failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return [
                'success' => false,
                'message' => 'Verification failed: ' . $e->getMessage()
            ];
        } finally {
            if (is_string($verificationHash)) {
                $this->cleanupVerificationFile($verificationHash);
            }
        }
    }

    private function createVerificationFile(string $hash): bool
    {
        try {
            if (!preg_match('/^[a-zA-Z0-9]{32,64}$/', $hash)) {
                Log::error('Invalid verification hash format', ['hash' => $hash]);
                return false;
            }
            
            $publicPath = public_path();
            $filename = basename("cybear-verification-{$hash}.html");
            $filepath = $publicPath . DIRECTORY_SEPARATOR . $filename;
            
            $realPublicPath = realpath($publicPath);
            $realFilePath = realpath(dirname($filepath));
            
            if (!$realPublicPath || !$realFilePath || $realFilePath !== $realPublicPath) {
                Log::error('Path traversal attempt detected', [
                    'hash' => $hash,
                    'attempted_path' => $filepath
                ]);
                return false;
            }

            $content = $hash . "\n<!-- Created: " . now()->toIso8601String() . " -->";
            
            $tempFile = $publicPath . DIRECTORY_SEPARATOR . '.' . $filename . '.tmp.' . bin2hex(random_bytes(6));
            $success = File::put($tempFile, $content);
            
            if ($success) {
                $success = File::move($tempFile, $filepath);
            }
            
            if ($success) {
                Log::info('Verification file created', ['file' => $filename]);
                return true;
            }

            File::delete($tempFile);
            Log::error('Failed to write verification file', ['file' => $filename]);
            return false;
            
        } catch (\Throwable $e) {
            Log::error('Failed to create verification file', [
                'hash' => $hash,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    private function cleanupVerificationFile(string $hash): void
    {
        try {
            $publicPath = public_path();
            $filename = basename("cybear-verification-{$hash}.html");
            $filepath = $publicPath . DIRECTORY_SEPARATOR . $filename;

            if (File::exists($filepath)) {
                File::delete($filepath);
                Log::info('Verification file cleaned up', ['file' => $filename]);
            }
        } catch (\Throwable $e) {
            Log::warning('Failed to cleanup verification file', [
                'hash' => $hash,
                'error' => $e->getMessage()
            ]);
        }
    }

    public function isVerified(): bool
    {
        return Cache::remember('cybear_domain_verified', 300, function() {
            try {
                $response = $this->apiClient->verifyAuth();
                if (($response['success'] ?? false) && isset($response['data']['is_verified'])) {
                    return $response['data']['is_verified'];
                }
                return false;
            } catch (\Throwable $e) {
                Log::error('Failed to check verification status', [
                    'error' => $e->getMessage()
                ]);
                return false;
            }
        });
    }
}
