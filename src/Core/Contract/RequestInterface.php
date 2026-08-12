<?php

namespace CybearCare\LaravelSecurity\Core\Contract;

interface RequestInterface
{
    public function getIp(): string;

    public function getUserAgent(): ?string;

    public function getFullUrl(): string;

    public function getPath(): string;

    public function getMethod(): string;

    public function getQueryString(): ?string;

    public function getAllInput(): array;

    /** @return array<string, mixed> */
    public function getQueryInput(): array;

    /** @return array<string, mixed> */
    public function getBodyInput(): array;

    public function getRawBody(): string;

    public function getHeaders(): array;

    public function getHeader(string $name, string $default = ''): string;

    public function getHost(): string;

    public function getInput(string $key, mixed $default = null): mixed;

    public function getRequestId(): ?string;

    public function getRouteName(): ?string;

    public function getRouteUri(): ?string;

    /** @return array<string, string>|null */
    public function getDastCorrelation(): ?array;
}
