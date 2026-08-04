<?php

namespace CybearCare\LaravelSecurity\Services;

class SecurityDataCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'security_data_collector';
    }

    protected function getConfigKey(): string
    {
        return 'security';
    }

    protected function collectData(): array
    {
        $data = [];
        
        if (config('cybear.collectors.security.scan_auth_config', true)) {
            $data['auth_config'] = $this->collectAuthConfig();
        }
        
        if (config('cybear.collectors.security.scan_database_config', true)) {
            $data['database_config'] = $this->collectDatabaseConfig();
        }
        
        if (config('cybear.collectors.security.scan_session_config', true)) {
            $data['session_config'] = $this->collectSessionConfig();
        }
        
        if (config('cybear.collectors.security.scan_csrf_config', true)) {
            $data['csrf_config'] = $this->collectCsrfConfig();
        }
        
        $data['encryption_config'] = $this->collectEncryptionConfig();
        
        if (config('cybear.collectors.security.scan_security_headers', false)) {
            $data['security_headers'] = $this->collectSecurityHeaders();
        }
        
        return $data;
    }

    protected function collectAuthConfig(): array
    {
        return [
            'default_guard' => config('auth.defaults.guard'),
            'guards' => array_keys(config('auth.guards', [])),
            'providers' => array_keys(config('auth.providers', [])),
            'password_timeout' => config('auth.password_timeout'),
        ];
    }

    protected function collectDatabaseConfig(): array
    {

        $defaultConnection = config('database.default');
        $connections = config('database.connections', []);
        
        return [
            'default_connection' => $defaultConnection,
            'driver' => $connections[$defaultConnection]['driver'] ?? null,
            'encryption' => !empty($connections[$defaultConnection]['options']) ? 'enabled' : 'disabled',

        ];
    }

    protected function collectSessionConfig(): array
    {
        return [
            'driver' => config('session.driver'),
            'lifetime' => config('session.lifetime'),
            'secure' => config('session.secure'),
            'http_only' => config('session.http_only'),
            'same_site' => config('session.same_site'),
        ];
    }

    protected function collectCsrfConfig(): array
    {
        return [
            'enabled' => class_exists(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class)
                || class_exists(\Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class),
            'token_lifetime' => config('session.lifetime'),
        ];
    }

    protected function collectEncryptionConfig(): array
    {
        return [
            'cipher' => config('app.cipher'),

            'key_configured' => !empty(config('app.key')),
        ];
    }

    protected function collectSecurityHeaders(): array
    {
        return [
            'hsts_enabled' => config('cybear.security_headers.hsts.enabled', false),
            'content_type_options' => config('cybear.security_headers.content_type_options', false),
            'frame_options' => config('cybear.security_headers.frame_options'),
            'xss_protection' => config('cybear.security_headers.xss_protection', false),
        ];
    }
}
