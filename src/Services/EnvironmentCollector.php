<?php

namespace CybearCare\LaravelSecurity\Services;

class EnvironmentCollector extends BaseDataCollector
{
    public function getCollectorName(): string
    {
        return 'environment_collector';
    }

    protected function getConfigKey(): string
    {
        return 'environment';
    }

    protected function collectData(): array
    {
        return [
            'php_config' => $this->collectPhpConfig(),
            'server_info' => $this->collectServerInfo(),
            'extensions' => $this->collectExtensions(),
            'security_functions' => $this->collectSecurityFunctions(),
        ];
    }

    protected function collectPhpConfig(): array
    {
        return [
            'version' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size'),
            'display_errors' => ini_get('display_errors'),
            'log_errors' => ini_get('log_errors'),
            'error_reporting' => error_reporting(),
        ];
    }

    protected function collectServerInfo(): array
    {
        return [
            'os' => PHP_OS,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '',
            'server_name' => $_SERVER['SERVER_NAME'] ?? '',
            'https' => isset($_SERVER['HTTPS']) ? 'enabled' : 'disabled',
        ];
    }

    protected function collectExtensions(): array
    {
        $securityExtensions = [
            'openssl', 'mcrypt', 'sodium', 'hash', 'filter',
            'curl', 'gd', 'mbstring', 'json', 'xml'
        ];

        $extensions = [];
        foreach ($securityExtensions as $ext) {
            $extensions[$ext] = extension_loaded($ext);
        }

        return $extensions;
    }

    protected function collectSecurityFunctions(): array
    {
        $securityFunctions = [
            'exec', 'shell_exec', 'system', 'passthru',
            'eval', 'file_get_contents', 'file_put_contents',
            'fopen', 'fwrite', 'include', 'require'
        ];

        $functions = [];
        $disabledFunctions = explode(',', ini_get('disable_functions'));
        
        foreach ($securityFunctions as $func) {
            $functions[$func] = !in_array($func, $disabledFunctions) && function_exists($func);
        }

        return $functions;
    }
}