<?php

namespace CybearCare\LaravelSecurity\Core\Headers;

class SecurityHeadersManager
{
    private array $config;

    private const DEFAULTS = [
        'hsts' => [
            'enabled' => true,
            'max_age' => 31536000, // 1 year
            'include_subdomains' => true,
            'preload' => false,
        ],
        'content_type_options' => true, // X-Content-Type-Options: nosniff (always)
        'frame_options' => 'DENY', // DENY, SAMEORIGIN, or false to disable
        'xss_protection' => false, // Deprecated, modern browsers ignore it. Set to '0' is safest.
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'permissions_policy' => 'camera=(), microphone=(), geolocation=(), payment=()',
        'coop' => 'same-origin', // Cross-Origin-Opener-Policy
        'corp' => 'same-origin', // Cross-Origin-Resource-Policy
        'coep' => false, // Cross-Origin-Embedder-Policy - disabled by default (breaks many sites)
        'csp' => null, // Content-Security-Policy - null means don't set (too app-specific for defaults)
        'csp_report_only' => null, // Content-Security-Policy-Report-Only
    ];

    public function __construct(array $config = [])
    {
        $this->config = array_merge(self::DEFAULTS, $config);
    }

    /**
     * Get all security headers that should be applied.
     * @return array<string, string> Header name => header value
     */
    public function getHeaders(): array
    {
        $headers = [];

        // HSTS
        $hsts = $this->config['hsts'];
        if (is_array($hsts) && ($hsts['enabled'] ?? true)) {
            $value = 'max-age=' . ($hsts['max_age'] ?? 31536000);
            if ($hsts['include_subdomains'] ?? true) {
                $value .= '; includeSubDomains';
            }
            if ($hsts['preload'] ?? false) {
                $value .= '; preload';
            }
            $headers['Strict-Transport-Security'] = $value;
        } elseif ($hsts === true) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
        }

        // X-Content-Type-Options
        if ($this->config['content_type_options']) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }

        // X-Frame-Options
        $frameOptions = $this->config['frame_options'];
        if ($frameOptions && $frameOptions !== false) {
            $headers['X-Frame-Options'] = strtoupper($frameOptions);
        }

        // X-XSS-Protection (deprecated but still set by some)
        if ($this->config['xss_protection'] !== false) {
            $headers['X-XSS-Protection'] = (string) $this->config['xss_protection'];
        }

        // Referrer-Policy
        if ($this->config['referrer_policy']) {
            $headers['Referrer-Policy'] = $this->config['referrer_policy'];
        }

        // Permissions-Policy
        if ($this->config['permissions_policy']) {
            $headers['Permissions-Policy'] = $this->config['permissions_policy'];
        }

        // Cross-Origin-Opener-Policy
        if ($this->config['coop']) {
            $headers['Cross-Origin-Opener-Policy'] = $this->config['coop'];
        }

        // Cross-Origin-Resource-Policy
        if ($this->config['corp']) {
            $headers['Cross-Origin-Resource-Policy'] = $this->config['corp'];
        }

        // Cross-Origin-Embedder-Policy
        if ($this->config['coep']) {
            $headers['Cross-Origin-Embedder-Policy'] = $this->config['coep'];
        }

        // Content-Security-Policy
        if ($this->config['csp']) {
            $headers['Content-Security-Policy'] = $this->config['csp'];
        }

        // Content-Security-Policy-Report-Only
        if ($this->config['csp_report_only']) {
            $headers['Content-Security-Policy-Report-Only'] = $this->config['csp_report_only'];
        }

        return $headers;
    }
}
