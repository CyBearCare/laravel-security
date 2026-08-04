<?php

namespace CybearCare\LaravelSecurity\Adapter;

use CybearCare\LaravelSecurity\Core\Contract\CacheInterface;
use Illuminate\Support\Facades\Cache;

class LaravelCacheAdapter implements CacheInterface
{
    public function get(string $key, mixed $default = null): mixed
    {
        return Cache::get($key, $default);
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        Cache::put($key, $value, $ttlSeconds);
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        return Cache::add($key, $value, $ttlSeconds);
    }

    public function has(string $key): bool
    {
        return Cache::has($key);
    }

    public function forget(string $key): void
    {
        Cache::forget($key);
    }

    public function increment(string $key): int
    {
        return Cache::increment($key);
    }

    public function remember(string $key, int $ttlSeconds, callable $callback): mixed
    {
        return Cache::remember($key, $ttlSeconds, $callback);
    }
}
