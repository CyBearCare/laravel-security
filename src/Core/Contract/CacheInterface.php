<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface CacheInterface
{
    public function get(string $key, mixed $default = null): mixed;

    public function put(string $key, mixed $value, int $ttlSeconds): void;

    public function add(string $key, mixed $value, int $ttlSeconds): bool;

    public function has(string $key): bool;

    public function forget(string $key): void;

    public function increment(string $key): int;

    public function remember(string $key, int $ttlSeconds, callable $callback): mixed;
}
