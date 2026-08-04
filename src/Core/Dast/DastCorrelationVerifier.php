<?php

namespace CybearCare\LaravelSecurity\Core\Dast;

use CybearCare\LaravelSecurity\Core\Config\CybearConfig;
use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use CybearCare\LaravelSecurity\Core\Contract\RequestInterface;
use JsonException;

final class DastCorrelationVerifier
{
    public const HEADER = 'X-Cybear-Scan-Correlation';

    public function __construct(
        private readonly CybearConfig $config,
        private readonly CacheInterface $cache,
    ) {}

    /**
     * @return array{
     *     status: 'absent'|'accepted'|'rejected',
     *     reason?: string,
     *     context?: array<string, string>
     * }
     */
    public function verify(RequestInterface $request): array
    {
        $token = $request->getHeader(self::HEADER);
        if ($token === '') {
            return ['status' => 'absent'];
        }

        if (! $this->config->isDastCorrelationEnabled()) {
            return $this->rejected('disabled');
        }

        $key = $this->config->getDastSigningKey();
        $audience = $this->config->getDastAudience();
        $deploymentId = $this->config->get('deployment_id');
        if ($key === null
            || strlen($key) < 32
            || $audience === null
            || ! is_string($deploymentId)
            || $deploymentId === '') {
            return $this->rejected('not_configured');
        }

        if (strlen($token) > 4096) {
            return $this->rejected('oversized');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== 'v1') {
            return $this->rejected('malformed');
        }

        $payloadJson = $this->base64UrlDecode($parts[1]);
        $providedSignature = $this->base64UrlDecode($parts[2]);
        if ($payloadJson === null
            || $providedSignature === null
            || strlen($payloadJson) > 2048
            || strlen($providedSignature) !== 32) {
            return $this->rejected('malformed');
        }

        $expectedSignature = hash_hmac('sha256', 'v1.'.$parts[1], $key, true);
        if (! hash_equals($expectedSignature, $providedSignature)) {
            return $this->rejected('signature');
        }

        try {
            $claims = json_decode($payloadJson, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->rejected('claims');
        }

        if (! $this->validClaims($claims)) {
            return $this->rejected('claims');
        }

        $now = time();
        $maximumTtl = max(30, min(3600, $this->config->getDastMaxTokenTtl()));
        if ($claims['iat'] > $now + 30
            || $claims['exp'] < $now
            || $maximumTtl < $claims['exp'] - $claims['iat']) {
            return $this->rejected('expired');
        }

        if (! hash_equals($this->config->getDastIssuer(), $claims['iss'])
            || ! hash_equals($audience, $claims['aud'])
            || ! hash_equals($deploymentId, $claims['deployment_id'])) {
            return $this->rejected('audience');
        }

        $path = '/'.ltrim($request->getPath(), '/');
        if (! hash_equals(strtoupper($request->getMethod()), $claims['method'])
            || ! hash_equals($path, $claims['path'])) {
            return $this->rejected('request_binding');
        }

        $nonceKey = 'cybear:dast:nonce:'.hash_hmac('sha256', $claims['nonce'], $key);
        if (! $this->cache->add($nonceKey, true, max(1, $claims['exp'] - $now))) {
            return $this->rejected('replay');
        }

        $routeFingerprint = hash('sha256', implode("\n", [
            $request->getMethod(),
            $request->getHost(),
            $request->getRouteUri() ?? $path,
            $request->getRouteName() ?? '',
        ]));

        return [
            'status' => 'accepted',
            'context' => [
                'scan_id' => $claims['scan_id'],
                'deployment_id' => $claims['deployment_id'],
                'route_fingerprint' => $routeFingerprint,
            ],
        ];
    }

    public function shouldLogRejection(RequestInterface $request, string $reason): bool
    {
        $key = hash('sha256', $request->getIp()."\n".$reason);

        return $this->cache->add('cybear:dast:rejection:'.$key, true, 60);
    }

    private function validClaims(mixed $claims): bool
    {
        if (! is_array($claims)) {
            return false;
        }

        foreach (['iss', 'aud', 'scan_id', 'deployment_id', 'nonce', 'method', 'path'] as $key) {
            if (! is_string($claims[$key] ?? null)
                || $claims[$key] === ''
                || strlen($claims[$key]) > 500) {
                return false;
            }
        }

        return is_int($claims['iat'] ?? null)
            && is_int($claims['exp'] ?? null)
            && preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/', $claims['scan_id']) === 1
            && preg_match('/^[A-Za-z0-9_-]{16,200}$/', $claims['nonce']) === 1
            && preg_match('/^[A-Z]{3,10}$/', $claims['method']) === 1
            && str_starts_with($claims['path'], '/')
            && ! str_contains($claims['path'], '?');
    }

    private function base64UrlDecode(string $value): ?string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            return null;
        }

        $padding = (4 - strlen($value) % 4) % 4;
        $decoded = base64_decode(
            strtr($value, '-_', '+/').str_repeat('=', $padding),
            true,
        );

        return is_string($decoded) ? $decoded : null;
    }

    /**
     * @return array{status: 'rejected', reason: string}
     */
    private function rejected(string $reason): array
    {
        return ['status' => 'rejected', 'reason' => $reason];
    }
}
