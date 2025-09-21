<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class AuthCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'auth';
    }

    protected function getConfigKey(): string
    {
        return 'auth';
    }

    protected function collectData(): array
    {
        return [
            'guards' => $this->getGuardConfigurations(),
            'providers' => $this->getProviderConfigurations(),
            'passwords' => $this->getPasswordConfigurations(),
            'user_statistics' => $this->getUserStatistics(),
            'session_config' => $this->getSessionConfiguration(),
            'two_factor' => $this->getTwoFactorConfiguration(),
            'social_auth' => $this->getSocialAuthConfiguration(),
        ];
    }

    protected function getGuardConfigurations(): array
    {
        $guards = [];
        $authConfig = config('auth.guards', []);
        
        foreach ($authConfig as $name => $config) {
            $guards[$name] = [
                'driver' => $config['driver'] ?? null,
                'provider' => $config['provider'] ?? null,
                'is_default' => $name === config('auth.defaults.guard'),
            ];
        }
        
        return $guards;
    }

    protected function getProviderConfigurations(): array
    {
        $providers = [];
        $providerConfig = config('auth.providers', []);
        
        foreach ($providerConfig as $name => $config) {
            $providers[$name] = [
                'driver' => $config['driver'] ?? null,
                'model' => $config['model'] ?? null,
                'table' => $config['table'] ?? null,
                'is_default' => $name === config('auth.defaults.passwords'),
            ];
        }
        
        return $providers;
    }

    protected function getPasswordConfigurations(): array
    {
        $passwords = [];
        $passwordConfig = config('auth.passwords', []);
        
        foreach ($passwordConfig as $name => $config) {
            $passwords[$name] = [
                'provider' => $config['provider'] ?? null,
                'table' => $config['table'] ?? null,
                'expire' => $config['expire'] ?? null,
                'throttle' => $config['throttle'] ?? null,
            ];
        }
        
        return $passwords;
    }

    protected function getUserStatistics(): array
    {
        try {
            $defaultProvider = config('auth.providers.' . config('auth.guards.web.provider'));
            
            if (!$defaultProvider || $defaultProvider['driver'] !== 'eloquent') {
                return ['error' => 'Cannot collect user statistics - not using eloquent driver'];
            }
            
            $userModel = $defaultProvider['model'];
            
            if (!class_exists($userModel)) {
                return ['error' => 'User model not found: ' . $userModel];
            }
            
            $query = $userModel::query();
            
            $stats = [
                'total_users' => $query->count(),
                'users_with_email_verified' => method_exists($userModel, 'hasVerifiedEmail') 
                    ? $query->whereNotNull('email_verified_at')->count() 
                    : null,
                'recent_users' => $query->where('created_at', '>=', now()->subDays(30))->count(),
                'active_users_last_login' => $this->getActiveUsersCount($userModel),
            ];
            
            return $stats;
            
        } catch (\Exception $e) {
            return ['error' => 'Failed to collect user statistics: ' . $e->getMessage()];
        }
    }

    protected function getActiveUsersCount(string $userModel): ?int
    {
        try {
            $model = new $userModel;
            
            if ($model->getConnection()->getSchemaBuilder()->hasColumn($model->getTable(), 'last_login_at')) {
                return $userModel::where('last_login_at', '>=', now()->subDays(30))->count();
            }
            
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    protected function getSessionConfiguration(): array
    {
        return [
            'driver' => config('session.driver'),
            'lifetime' => config('session.lifetime'),
            'expire_on_close' => config('session.expire_on_close'),
            'encrypt' => config('session.encrypt'),
            'files' => config('session.files'),
            'connection' => config('session.connection'),
            'table' => config('session.table'),
            'store' => config('session.store'),
            'lottery' => config('session.lottery'),
            'cookie' => config('session.cookie'),
            'path' => config('session.path'),
            'domain' => config('session.domain'),
            'secure' => config('session.secure'),
            'http_only' => config('session.http_only'),
            'same_site' => config('session.same_site'),
        ];
    }

    protected function getTwoFactorConfiguration(): array
    {
        $config = [];
        
        // Check for common 2FA packages
        if (class_exists('Laravel\\Fortify\\FortifyServiceProvider')) {
            $config['fortify'] = [
                'enabled' => config('fortify.features.two-factor-authentication', false),
                'features' => config('fortify.features', []),
            ];
        }
        
        if (class_exists('PragmaRX\\Google2FA\\Google2FA')) {
            $config['google2fa'] = ['installed' => true];
        }
        
        return $config;
    }

    protected function getSocialAuthConfiguration(): array
    {
        $config = [];
        
        // Check for Laravel Socialite
        if (class_exists('Laravel\\Socialite\\SocialiteServiceProvider')) {
            $socialiteConfig = config('services', []);
            $providers = [];
            
            foreach (['github', 'google', 'facebook', 'twitter', 'linkedin', 'bitbucket'] as $provider) {
                if (isset($socialiteConfig[$provider])) {
                    $providers[$provider] = [
                        'configured' => !empty($socialiteConfig[$provider]['client_id']),
                        'has_secret' => !empty($socialiteConfig[$provider]['client_secret']),
                        'redirect' => $socialiteConfig[$provider]['redirect'] ?? null,
                    ];
                }
            }
            
            $config['socialite'] = [
                'installed' => true,
                'providers' => $providers,
            ];
        }
        
        return $config;
    }
}