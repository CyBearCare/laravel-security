<?php

namespace CybearCare\LaravelSecurity\Posture\Checks;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\Severity;

final class EnvironmentFilePermissionsCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'laravel.filesystem.env_permissions';
    }

    public function name(): string
    {
        return 'Environment file permissions';
    }

    public function category(): string
    {
        return 'filesystem';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function run(CheckContext $context): CheckResult
    {
        if (DIRECTORY_SEPARATOR !== '/') {
            return $this->skipped('POSIX file permissions are not available on this platform.');
        }

        $path = $context->basePath('.env');
        if (!is_file($path)) {
            return $this->skipped('No .env file exists in the application root.');
        }

        $permissions = fileperms($path);
        if ($permissions === false) {
            return $this->skipped('The .env file permissions could not be read.');
        }

        $mode = $permissions & 0777;
        $evidence = ['mode' => sprintf('%04o', $mode)];
        $dangerous = ($mode & 0007) !== 0 || ($mode & 0020) !== 0;

        if ($dangerous) {
            return $this->fail(
                'The .env file is accessible to other users or writable by its group.',
                'Restrict .env ownership to the deployment user and use permissions such as 0600 or 0640 where a trusted group must read it.',
                $evidence,
            );
        }

        if (($mode & 0040) !== 0) {
            return $this->warning(
                'The .env file is readable by its group.',
                'Confirm the group contains only trusted application operators; otherwise restrict the file to 0600.',
                $evidence,
                Severity::Low,
            );
        }

        return $this->pass('The .env file is not accessible to group or other users.', $evidence);
    }
}
