<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class DomainVerificationService
{
    protected CybearApiClient $apiClient;

    public function __construct(CybearApiClient $apiClient)
    {
        $this->apiClient = $apiClient;
    }

    /**
     * Automatically handle domain verification process
     */
    public function autoVerify(): array
    {
        // Implement rate limiting for verification attempts
        $key = 'cybear-verify:' . request()->ip();
        
        if (!RateLimiter::attempt($key, 5, function() {}, 60)) {
            Log::warning('Domain verification rate limit exceeded', [
                'ip' => request()->ip()
            ]);
            
            return [
                'success' => false,
                'message' => 'Too many verification attempts. Please try again later.'
            ];
        }
        
        try {
            // Step 1: Check if verification is needed
            $response = $this->apiClient->initOrActivate();
            
            if (!$response['success']) {
                return [
                    'success' => false,
                    'message' => 'Failed to initialize: ' . ($response['message'] ?? 'Unknown error')
                ];
            }

            $data = $response['data'];

            // If already activated, return success
            if ($data['is_activated'] ?? false) {
                return [
                    'success' => true,
                    'message' => 'Domain is already verified and activated',
                    'status' => 'activated'
                ];
            }

            // If verification is needed
            if (($data['next_step'] ?? '') === 'verify') {
                $verificationHash = $data['verification_hash'];
                
                Log::info('Domain verification required', [
                    'hash' => $verificationHash,
                    'url' => $data['verification_url'] ?? null
                ]);

                // Step 2: Create verification file
                if (!$this->createVerificationFile($verificationHash)) {
                    return [
                        'success' => false,
                        'message' => 'Failed to create verification file'
                    ];
                }

                // Step 3: Verify domain
                $verifyResponse = $this->apiClient->verify();
                
                if (!$verifyResponse['success']) {
                    $this->cleanupVerificationFile($verificationHash);
                    return [
                        'success' => false,
                        'message' => 'Domain verification failed: ' . ($verifyResponse['message'] ?? 'Unknown error')
                    ];
                }

                // Step 4: Cleanup
                $this->cleanupVerificationFile($verificationHash);

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

        } catch (\Exception $e) {
            Log::error('Auto verification failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return [
                'success' => false,
                'message' => 'Verification failed: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Create verification file in public directory
     */
    private function createVerificationFile(string $hash): bool
    {
        try {
            // Validate hash format to prevent directory traversal
            if (!preg_match('/^[a-zA-Z0-9]{32,64}$/', $hash)) {
                Log::error('Invalid verification hash format', ['hash' => $hash]);
                return false;
            }
            
            $publicPath = public_path();
            // Use basename to prevent directory traversal
            $filename = basename("cybear-verification-{$hash}.html");
            $filepath = $publicPath . DIRECTORY_SEPARATOR . $filename;
            
            // Additional safety check
            $realPublicPath = realpath($publicPath);
            $realFilePath = dirname($filepath);
            
            if (!$realPublicPath || strpos($realFilePath, $realPublicPath) !== 0) {
                Log::error('Path traversal attempt detected', [
                    'hash' => $hash,
                    'attempted_path' => $filepath
                ]);
                return false;
            }

            // Create the verification file with just the hash
            // Add a timestamp to prevent old files from being used
            $content = $hash . "\n<!-- Created: " . now()->toIso8601String() . " -->";
            
            // Use atomic file write to prevent race conditions
            $tempFile = $filepath . '.tmp.' . uniqid();
            $success = File::put($tempFile, $content);
            
            if ($success) {
                // Atomic move
                $success = File::move($tempFile, $filepath);
            }
            
            if ($success) {
                Log::info('Verification file created', ['file' => $filename]);
                return true;
            }

            Log::error('Failed to write verification file', ['file' => $filename]);
            return false;
            
        } catch (\Exception $e) {
            Log::error('Failed to create verification file', [
                'hash' => $hash,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Clean up verification file after successful verification
     */
    private function cleanupVerificationFile(string $hash): void
    {
        try {
            $publicPath = public_path();
            // Use basename to prevent directory traversal
            $filename = basename("cybear-verification-{$hash}.html");
            $filepath = $publicPath . DIRECTORY_SEPARATOR . $filename;

            if (File::exists($filepath)) {
                File::delete($filepath);
                Log::info('Verification file cleaned up', ['file' => $filename]);
            }
        } catch (\Exception $e) {
            Log::warning('Failed to cleanup verification file', [
                'hash' => $hash,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Check if domain is verified
     */
    public function isVerified(): bool
    {
        // Cache verification status to reduce API calls
        return Cache::remember('cybear_domain_verified', 300, function() {
            try {
                $response = $this->apiClient->verifyAuth();
                if ($response['success'] && isset($response['data']['is_verified'])) {
                    return $response['data']['is_verified'];
                }
                return false;
            } catch (\Exception $e) {
                Log::error('Failed to check verification status', [
                    'error' => $e->getMessage()
                ]);
                return false;
            }
        });
    }
}