# Cybear Laravel Security

Laravel-native security posture, runtime telemetry, WAF monitoring, and DAST context for Laravel 12 and 13.

The package is standalone. It uses Laravel's own routing, middleware, events, cache, HTTP client, encryption, scheduler, and Eloquent integration.

> This package is under active development.

## What it provides

- `cybear:scan` with 37 explainable, capability-aware Laravel posture checks
- table output for developers and versioned JSON for CI
- stable occurrence fingerprints, source locations, severity, confidence, evidence, and remediation
- CI baselines and expiring, reasoned suppressions that preserve new-finding detection
- optional APP_KEY-encrypted outbox delivery to Cybear
- monitor-first, route-aware WAF evaluation
- exact rule scoping, expiry, versioning, and deterministic staged rollout
- deployment-bound, replay-resistant DAST correlation
- authentication and security-event auditing
- package, route, middleware, environment, and deployment inventory
- safe API behavior without assuming browser sessions
- privacy-safe defaults with no request-body or query-value capture

## Requirements

- PHP 8.2+
- Laravel 12 or 13
- a Laravel-supported database for telemetry and SaaS delivery

## Start with a local posture scan

```bash
composer require cybear-care/laravel-security
php artisan cybear:scan
```

The local scan works with `CYBEAR_ENABLED=false` and without an API key. It is read-only unless `--output` or `--send` is supplied.

Four checks perform bounded, local-only inspection of application controller and FormRequest methods for Laravel authorization, mass-assignment, upload-validation, and signed-link signals. Target methods are never invoked, vendor code is excluded, and source text is never placed in a report or sent to Cybear.

```bash
php artisan cybear:scan --format=json --fail-on=high
php artisan cybear:scan --output=storage/app/cybear-posture.json
php artisan cybear:scan --baseline=cybear-baseline.json --ci
```

## Enable runtime integration

```bash
php artisan cybear:setup
```

Setup publishes configuration, runs migrations, verifies the application, and synchronizes rules before enabling the package. WAF protection begins in `monitor` mode.

Use `php artisan cybear:status` to review the active configuration, connection state, collection health, and WAF state. Run `php artisan cybear:sync` after changing remote protection rules.
