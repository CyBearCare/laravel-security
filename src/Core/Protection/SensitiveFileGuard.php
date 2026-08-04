<?php

namespace CybearCare\LaravelSecurity\Core\Protection;

class SensitiveFileGuard
{
    /**
     * File paths/patterns to block (case-insensitive matching).
     * These are matched against the request URI path.
     */
    private const DEFAULT_BLOCKED_PATHS = [
        // Environment files
        '/.env',
        '/.env.backup',
        '/.env.local',
        '/.env.production',
        '/.env.staging',
        '/.env.testing',
        '/.env.example',

        // Version control
        '/.git',
        '/.gitignore',
        '/.gitattributes',
        '/.svn',
        '/.hg',

        // Composer / NPM
        '/composer.json',
        '/composer.lock',
        '/package.json',
        '/package-lock.json',
        '/yarn.lock',
        '/pnpm-lock.yaml',

        // IDE / Editor
        '/.idea',
        '/.vscode',
        '/.editorconfig',

        // CI/CD
        '/.github',
        '/.gitlab-ci.yml',
        '/.circleci',
        '/Dockerfile',
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/Vagrantfile',

        // PHP configuration
        '/phpunit.xml',
        '/phpunit.xml.dist',
        '/phpstan.neon',
        '/phpstan.neon.dist',
        '/phpcs.xml',
        '/phpcs.xml.dist',
        '/.php-cs-fixer.php',
        '/.php-cs-fixer.dist.php',

        // Other sensitive files
        '/wp-config.php',
        '/web.config',
        '/.htaccess',
        '/.htpasswd',
        '/Makefile',
        '/Gruntfile.js',
        '/Gulpfile.js',
        '/webpack.mix.js',
        '/vite.config.js',
        '/vite.config.ts',
    ];

    /**
     * Patterns matched against the URI path (regex).
     */
    private const DEFAULT_BLOCKED_PATTERNS = [
        // Any .env file variant
        '#/\.env(\.[a-zA-Z0-9_-]+)?$#i',
        // Any dotfile/dotdirectory at the root
        '#^/\.[a-zA-Z]#',
        // Backup/temp files
        '#\.(bak|old|swp|swo|tmp|save|orig|dist|log)$#i',
        // SQL dumps
        '#\.(sql|sql\.gz|sql\.bz2|sql\.zip)$#i',
        // PHP backup files
        '#\.php\.(bak|old|save|orig|dist|~)$#i',
        // Editor temp files
        '#~$#',
        // phpinfo
        '#/(phpinfo|php_info|info|test)\.php$#i',
    ];

    private array $blockedPaths;
    private array $blockedPatterns;
    private array $allowedPaths;
    private bool $enabled;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->blockedPaths = array_merge(
            self::DEFAULT_BLOCKED_PATHS,
            $config['additional_blocked_paths'] ?? []
        );
        $this->blockedPatterns = array_merge(
            self::DEFAULT_BLOCKED_PATTERNS,
            $config['additional_blocked_patterns'] ?? []
        );
        $this->allowedPaths = $config['allowed_paths'] ?? [];
    }

    /**
     * Check if a request path should be blocked.
     *
     * @param string $path The URL path (e.g., "/.env" or "/.git/config")
     * @return array{blocked: bool, reason: ?string}
     */
    public function check(string $path): array
    {
        if (!$this->enabled) {
            return ['blocked' => false, 'reason' => null];
        }

        $path = parse_url($path, PHP_URL_PATH) ?? $path;
        for ($i = 0; $i < 2; $i++) {
            $decoded = rawurldecode($path);
            if ($decoded === $path) {
                break;
            }
            $path = $decoded;
        }
        $path = '/' . ltrim(str_replace('\\', '/', str_replace("\0", '', $path)), '/');
        $normalizedPath = strtolower($path);

        // Check allowlist first
        foreach ($this->allowedPaths as $allowed) {
            $allowed = '/' . trim(strtolower((string) $allowed), '/');
            if ($allowed === $normalizedPath || str_starts_with($normalizedPath, $allowed . '/')) {
                return ['blocked' => false, 'reason' => null];
            }
        }

        // Check exact paths (with prefix matching for directories like .git/)
        foreach ($this->blockedPaths as $blocked) {
            $blockedLower = strtolower($blocked);
            if ($normalizedPath === $blockedLower || str_starts_with($normalizedPath, $blockedLower . '/')) {
                return ['blocked' => true, 'reason' => "Blocked sensitive path: {$blocked}"];
            }
        }

        // Check regex patterns
        foreach ($this->blockedPatterns as $pattern) {
            if (@preg_match($pattern, $path) === 1) {
                return ['blocked' => true, 'reason' => "Blocked by pattern: {$pattern}"];
            }
        }

        return ['blocked' => false, 'reason' => null];
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}
