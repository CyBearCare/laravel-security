<?php

namespace CybearCare\LaravelSecurity\Services;

use CybearCare\LaravelSecurity\Models\ThreatEvent;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

final class ThreatReporter
{
    public const SIGNATURE_CATALOG_VERSION = '2026-08-12.1';

    private const OBSERVED_ATTRIBUTE = 'cybear_threat_observed';

    private const AUTH_OBSERVED_ATTRIBUTE = 'cybear_auth_threat_observed';

    /** @var array<string, string> */
    private const PATTERNS = [
        'sql_injection' => '/(?:\bunion\b.{0,120}\bselect\b|\bor\b(?:\s|\/\*[\s\S]{0,80}?\*\/){1,8}[0-9\'\"]+\s*=\s*[0-9\'\"]+|\bsleep\s*\(|\bbenchmark\s*\()/iu',
        'cross_site_scripting' => '/(?:<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover)\s*=|<\s*(?:iframe|svg|img)\b)/iu',
        'command_injection' => '/(?:[;&|`]\s*(?:cat|curl|wget|bash|sh|powershell|cmd|nc|whoami|id)\b|\$\([^)]{1,200}\))/iu',
        'path_traversal' => '~(?:\.\.[\\/]|%2e%2e(?:%2f|%5c)|%252e%252e(?:%252f|%255c))~iu',
        'file_inclusion' => '~(?:\b(?:file|php|data|expect|zip|phar)://|/proc/self/environ|(?:^|[\\/])etc[\\/]passwd)~iu',
    ];

    public function observe(Request $request): ?ThreatEvent
    {
        if (! config('cybear.threat_reporting.enabled', true)
            || $request->attributes->getBoolean(self::OBSERVED_ATTRIBUTE)) {
            return null;
        }

        $request->attributes->set(self::OBSERVED_ATTRIBUTE, true);
        $signal = $this->detect($request);
        if ($signal === null) {
            return null;
        }

        $ip = $request->ip();
        if (! is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        if (! $this->claimSample($request, $ip, $signal)) {
            return null;
        }

        $eventId = 'laravel-'.Str::uuid();
        $requestContext = [
            'method' => strtoupper($request->method()),
        ];
        $routeTemplate = $this->routeTemplate($request);
        if ($routeTemplate !== null) {
            $requestContext['route_template'] = $routeTemplate;
        }
        if ($signal['parameter'] !== null) {
            $requestContext['parameter'] = $signal['parameter'];
        }

        $payload = [
            'event_id' => $eventId,
            'occurred_at' => now()->toISOString(),
            'detector' => 'laravel.request-sensor',
            'category' => $signal['category'],
            'severity' => 'high',
            'confidence' => 0.99,
            'source' => [
                'ip' => $ip,
                'user_agent_hash' => hash('sha256', (string) $request->userAgent()),
            ],
            'request' => $requestContext,
            'outcome' => ['action' => 'observed'],
            'context' => [
                'signal_location' => $signal['location'],
                'signature_catalog_version' => self::SIGNATURE_CATALOG_VERSION,
            ],
        ];

        return $this->enqueue($eventId, $payload);
    }

    public function reportAuthenticationFailure(Request $request, bool $lockedOut = false): ?ThreatEvent
    {
        if (! config('cybear.threat_reporting.enabled', true)
            || $request->attributes->getBoolean(self::AUTH_OBSERVED_ATTRIBUTE)) {
            return null;
        }

        $request->attributes->set(self::AUTH_OBSERVED_ATTRIBUTE, true);
        $ip = $request->ip();
        if (! is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $eventId = 'laravel-'.Str::uuid();
        $requestContext = ['method' => strtoupper($request->method())];
        $routeTemplate = $this->routeTemplate($request);
        if ($routeTemplate !== null) {
            $requestContext['route_template'] = $routeTemplate;
        }

        return $this->enqueue($eventId, [
            'event_id' => $eventId,
            'occurred_at' => now()->toISOString(),
            'detector' => 'laravel.authentication',
            'category' => 'authentication_abuse',
            'severity' => $lockedOut ? 'high' : 'medium',
            'confidence' => 0.98,
            'source' => [
                'ip' => $ip,
                'user_agent_hash' => hash('sha256', (string) $request->userAgent()),
            ],
            'request' => $requestContext,
            'outcome' => ['action' => $lockedOut ? 'rate_limited' : 'observed'],
            'context' => ['authentication_state' => 'guest'],
        ]);
    }

    /** @return array{category: string, location: string, parameter: string|null}|null */
    private function detect(Request $request): ?array
    {
        $surfaces = [
            'path' => (string) $request->getPathInfo(),
            'query' => (string) $request->server('QUERY_STRING', ''),
            'body' => (string) $request->getContent(),
        ];

        foreach ($surfaces as $location => $value) {
            $category = $this->categoryFor($value);
            if ($category === null) {
                continue;
            }

            return [
                'category' => $category,
                'location' => $location,
                'parameter' => $this->parameterFor($request, $location, $category),
            ];
        }

        return null;
    }

    private function categoryFor(string $value): ?string
    {
        foreach ($this->canonicalVariants($value) as $variant) {
            foreach (self::PATTERNS as $category => $pattern) {
                if (@preg_match($pattern, $variant) === 1) {
                    return $category;
                }
            }
        }

        return null;
    }

    private function parameterFor(Request $request, string $location, string $category): ?string
    {
        $parameters = match ($location) {
            'query' => $request->query->all(),
            'body' => $request->request->all(),
            default => [],
        };
        $inspected = 0;

        foreach ($this->flatten($parameters) as $name => $value) {
            if (++$inspected > 100 || $this->categoryFor($value) !== $category) {
                continue;
            }

            $name = substr((string) $name, 0, 128);

            return preg_match('/^[A-Za-z0-9_.\[\]-]+$/', $name) === 1 ? $name : null;
        }

        return null;
    }

    /** @return array<string, string> */
    private function flatten(array $parameters, string $prefix = '', int $depth = 0): array
    {
        if ($depth >= 6) {
            return [];
        }

        $flattened = [];

        foreach ($parameters as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix.'.'.$key;
            if (is_array($value)) {
                $flattened += $this->flatten($value, $name, $depth + 1);
            } elseif (is_scalar($value) || $value === null) {
                $flattened[$name] = (string) $value;
            }

            if (count($flattened) >= 100) {
                break;
            }
        }

        return $flattened;
    }

    /** @return list<string> */
    private function canonicalVariants(string $value): array
    {
        $maximumBytes = max(1024, min(131072, (int) config(
            'cybear.threat_reporting.max_inspection_bytes',
            32768,
        )));
        $passes = max(1, min(8, (int) config('cybear.threat_reporting.max_decode_passes', 6)));
        $current = strlen($value) <= $maximumBytes
            ? $value
            : substr($value, 0, intdiv($maximumBytes, 2))
                ."\n"
                .substr($value, -($maximumBytes - intdiv($maximumBytes, 2)));
        $variants = [];

        for ($pass = 0; $pass < $passes; $pass++) {
            if (! in_array($current, $variants, true)) {
                $variants[] = $current;
            }

            $decoded = html_entity_decode(
                rawurldecode(str_replace('+', ' ', $current)),
                ENT_QUOTES | ENT_HTML5,
                'UTF-8',
            );
            $decoded = substr($decoded, 0, $maximumBytes);
            if ($decoded === $current) {
                break;
            }
            $current = $decoded;
        }

        return $variants;
    }

    /** @param array{category: string, location: string, parameter: string|null} $signal */
    private function claimSample(Request $request, string $ip, array $signal): bool
    {
        $seconds = max(0, min(3600, (int) config('cybear.threat_reporting.sample_seconds', 10)));
        if ($seconds === 0) {
            return true;
        }

        $route = $this->routeTemplate($request) ?? $request->path();
        $key = 'cybear:threat-sample:'.hash('sha256', implode("\0", [
            $ip,
            $signal['category'],
            $signal['location'],
            $signal['parameter'] ?? '*',
            strtoupper($request->method()),
            $route,
        ]));

        return Cache::add($key, true, $seconds);
    }

    private function routeTemplate(Request $request): ?string
    {
        $route = $request->route();
        if (! is_object($route) || ! method_exists($route, 'uri')) {
            return null;
        }

        $template = '/'.ltrim((string) $route->uri(), '/');
        $templateWithoutPlaceholders = preg_replace(
            '/\{[A-Za-z0-9_.-]+\??\}/',
            '{parameter}',
            $template,
        );
        if (strlen($template) > 500
            || ! is_string($templateWithoutPlaceholders)
            || str_contains($templateWithoutPlaceholders, '?')
            || str_contains($template, '#')
            || preg_match('/[\r\n]/', $template) === 1) {
            return null;
        }

        return $template;
    }

    private function makeRoom(): void
    {
        $maximum = max(100, min(50000, (int) config(
            'cybear.threat_reporting.max_outbox_records',
            5000,
        )));
        $overflow = ThreatEvent::query()->count() - $maximum + 1;
        if ($overflow <= 0) {
            return;
        }

        $transmitted = ThreatEvent::query()
            ->where('transmitted', true)
            ->orderBy('id')
            ->limit($overflow)
            ->pluck('id');
        ThreatEvent::query()->whereKey($transmitted->all())->delete();
        $overflow -= $transmitted->count();

        if ($overflow > 0) {
            $oldest = ThreatEvent::query()->orderBy('id')->limit($overflow)->pluck('id');
            ThreatEvent::query()->whereKey($oldest->all())->delete();
        }
    }

    /** @param array<string, mixed> $payload */
    private function enqueue(string $eventId, array $payload): ThreatEvent
    {
        $this->makeRoom();

        return ThreatEvent::query()->create([
            'event_id' => $eventId,
            'payload' => $payload,
        ]);
    }
}
