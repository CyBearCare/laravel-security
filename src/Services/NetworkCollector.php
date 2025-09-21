<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

class NetworkCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'network';
    }

    protected function getConfigKey(): string
    {
        return 'network';
    }

    protected function collectData(): array
    {
        return [
            'server_info' => $this->getServerInformation(),
            'network_config' => $this->getNetworkConfiguration(),
            'ssl_config' => $this->getSslConfiguration(),
            'proxy_config' => $this->getProxyConfiguration(),
            'cors_config' => $this->getCorsConfiguration(),
            'rate_limiting' => $this->getRateLimitingConfiguration(),
            'domain_config' => $this->getDomainConfiguration(),
        ];
    }

    protected function getServerInformation(): array
    {
        $serverInfo = [];
        
        try {
            // Server software
            $serverInfo['server_software'] = $_SERVER['SERVER_SOFTWARE'] ?? 'unknown';
            $serverInfo['server_name'] = $_SERVER['SERVER_NAME'] ?? 'unknown';
            $serverInfo['server_port'] = $_SERVER['SERVER_PORT'] ?? 'unknown';
            $serverInfo['https'] = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            
            // Request information
            $serverInfo['request_method'] = $_SERVER['REQUEST_METHOD'] ?? 'unknown';
            $serverInfo['request_uri'] = $_SERVER['REQUEST_URI'] ?? 'unknown';
            $serverInfo['query_string'] = $_SERVER['QUERY_STRING'] ?? '';
            
            // Client information
            $serverInfo['remote_addr'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $serverInfo['remote_port'] = $_SERVER['REMOTE_PORT'] ?? 'unknown';
            $serverInfo['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            // Headers
            $serverInfo['accept_encoding'] = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
            $serverInfo['accept_language'] = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
            $serverInfo['cache_control'] = $_SERVER['HTTP_CACHE_CONTROL'] ?? '';
            
        } catch (\Exception $e) {
            $serverInfo['error'] = 'Failed to collect server info: ' . $e->getMessage();
        }
        
        return $serverInfo;
    }

    protected function getNetworkConfiguration(): array
    {
        $config = [];
        
        try {
            // Laravel URL configuration
            $config['app_url'] = config('app.url');
            $config['asset_url'] = config('app.asset_url');
            $config['mix_url'] = config('app.mix_url');
            
            // Trusted proxies
            $config['trusted_proxies'] = config('trustedproxy.proxies', []);
            $config['trusted_headers'] = config('trustedproxy.headers', []);
            
            // Session configuration
            $config['session_domain'] = config('session.domain');
            $config['session_secure'] = config('session.secure');
            $config['session_same_site'] = config('session.same_site');
            
        } catch (\Exception $e) {
            $config['error'] = 'Failed to collect network configuration: ' . $e->getMessage();
        }
        
        return $config;
    }

    protected function getSslConfiguration(): array
    {
        $sslConfig = [];
        
        try {
            // Check if HTTPS is enforced
            $sslConfig['https_enforced'] = config('app.url', '') !== '' && 
                                         str_starts_with(config('app.url'), 'https://');
            
            // SSL detection from server
            $sslConfig['ssl_active'] = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            $sslConfig['ssl_protocol'] = $_SERVER['SSL_PROTOCOL'] ?? null;
            $sslConfig['ssl_cipher'] = $_SERVER['SSL_CIPHER'] ?? null;
            
            // Security headers related to SSL
            $sslConfig['hsts_enabled'] = $this->checkHstsEnabled();
            $sslConfig['secure_cookies'] = config('session.secure', false);
            
        } catch (\Exception $e) {
            $sslConfig['error'] = 'Failed to collect SSL configuration: ' . $e->getMessage();
        }
        
        return $sslConfig;
    }

    protected function getProxyConfiguration(): array
    {
        $proxyConfig = [];
        
        try {
            // Check for proxy headers
            $proxyHeaders = [
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED_PROTO',
                'HTTP_X_FORWARDED_HOST',
                'HTTP_X_REAL_IP',
                'HTTP_X_FORWARDED_PORT',
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_CF_RAY', // Cloudflare
            ];
            
            $detectedHeaders = [];
            foreach ($proxyHeaders as $header) {
                if (isset($_SERVER[$header])) {
                    $detectedHeaders[$header] = 'present';
                }
            }
            
            $proxyConfig['detected_headers'] = $detectedHeaders;
            $proxyConfig['behind_proxy'] = !empty($detectedHeaders);
            
            // Laravel trusted proxy configuration
            $proxyConfig['trusted_proxies'] = config('trustedproxy.proxies', []);
            $proxyConfig['proxy_headers'] = config('trustedproxy.headers', []);
            
            // Cloudflare detection
            $proxyConfig['cloudflare_detected'] = isset($_SERVER['HTTP_CF_RAY']);
            
        } catch (\Exception $e) {
            $proxyConfig['error'] = 'Failed to collect proxy configuration: ' . $e->getMessage();
        }
        
        return $proxyConfig;
    }

    protected function getCorsConfiguration(): array
    {
        $corsConfig = [];
        
        try {
            // Check if Laravel CORS package is installed
            if (class_exists('Fruitcake\\Cors\\CorsServiceProvider')) {
                $corsConfig['package'] = 'fruitcake/laravel-cors';
                $corsConfig['config'] = [
                    'paths' => config('cors.paths', []),
                    'allowed_methods' => config('cors.allowed_methods', []),
                    'allowed_origins' => config('cors.allowed_origins', []),
                    'allowed_origins_patterns' => config('cors.allowed_origins_patterns', []),
                    'allowed_headers' => config('cors.allowed_headers', []),
                    'exposed_headers' => config('cors.exposed_headers', []),
                    'max_age' => config('cors.max_age', 0),
                    'supports_credentials' => config('cors.supports_credentials', false),
                ];
            } else {
                $corsConfig['package'] = 'not_installed';
            }
            
        } catch (\Exception $e) {
            $corsConfig['error'] = 'Failed to collect CORS configuration: ' . $e->getMessage();
        }
        
        return $corsConfig;
    }

    protected function getRateLimitingConfiguration(): array
    {
        $rateLimitConfig = [];
        
        try {
            // Laravel built-in rate limiting
            $rateLimitConfig['throttle_middleware'] = $this->checkThrottleMiddleware();
            
            // API rate limiting
            $rateLimitConfig['api_rate_limit'] = config('app.api_rate_limit');
            
            // Cache configuration for rate limiting
            $rateLimitConfig['cache_driver'] = config('cache.default');
            $rateLimitConfig['redis_available'] = extension_loaded('redis') && 
                                                config('database.redis.default.host');
            
        } catch (\Exception $e) {
            $rateLimitConfig['error'] = 'Failed to collect rate limiting configuration: ' . $e->getMessage();
        }
        
        return $rateLimitConfig;
    }

    protected function getDomainConfiguration(): array
    {
        $domainConfig = [];
        
        try {
            // Current domain information
            $domainConfig['current_domain'] = request()->getHost();
            $domainConfig['current_scheme'] = request()->getScheme();
            $domainConfig['current_port'] = request()->getPort();
            
            // Configured domains
            $domainConfig['app_url'] = config('app.url');
            $domainConfig['session_domain'] = config('session.domain');
            
            // Subdomain routing
            $domainConfig['subdomain_routing'] = $this->checkSubdomainRouting();
            
        } catch (\Exception $e) {
            $domainConfig['error'] = 'Failed to collect domain configuration: ' . $e->getMessage();
        }
        
        return $domainConfig;
    }

    protected function checkHstsEnabled(): bool
    {
        try {
            // Check if HSTS middleware is applied or headers are set
            $middleware = app('router')->getMiddleware();
            
            foreach ($middleware as $name => $class) {
                if (str_contains(strtolower($class), 'hsts') || 
                    str_contains(strtolower($name), 'hsts')) {
                    return true;
                }
            }
            
            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    protected function checkThrottleMiddleware(): array
    {
        try {
            $throttleRoutes = [];
            $routes = Route::getRoutes()->getRoutes();
            
            foreach ($routes as $route) {
                $middleware = $route->middleware();
                
                foreach ($middleware as $m) {
                    if (str_starts_with($m, 'throttle:')) {
                        $throttleRoutes[] = [
                            'uri' => $route->uri(),
                            'methods' => $route->methods(),
                            'throttle' => $m,
                        ];
                        break;
                    }
                }
            }
            
            return [
                'enabled' => !empty($throttleRoutes),
                'routes_count' => count($throttleRoutes),
                'examples' => array_slice($throttleRoutes, 0, 5), // First 5 examples
            ];
            
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    protected function checkSubdomainRouting(): array
    {
        try {
            $subdomainRoutes = [];
            $routes = Route::getRoutes()->getRoutes();
            
            foreach ($routes as $route) {
                $domain = $route->getDomain();
                if ($domain && str_contains($domain, '{')) {
                    $subdomainRoutes[] = [
                        'domain' => $domain,
                        'uri' => $route->uri(),
                        'methods' => $route->methods(),
                    ];
                }
            }
            
            return [
                'enabled' => !empty($subdomainRoutes),
                'routes_count' => count($subdomainRoutes),
                'examples' => array_slice($subdomainRoutes, 0, 3),
            ];
            
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}