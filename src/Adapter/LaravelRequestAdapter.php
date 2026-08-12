<?php

namespace CybearCare\LaravelSecurity\Adapter;

use CybearCare\LaravelSecurity\Core\Contract\RequestInterface;
use Illuminate\Http\Request;

class LaravelRequestAdapter implements RequestInterface
{
    protected Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function getIp(): string
    {
        $ip = $this->request->ip();

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)
            ? $ip
            : '0.0.0.0';
    }

    public function getUserAgent(): ?string
    {
        $agent = $this->request->userAgent();

        return is_string($agent) ? substr($agent, 0, 2000) : null;
    }

    public function getFullUrl(): string
    {
        return $this->request->fullUrl();
    }

    public function getPath(): string
    {
        return $this->request->path();
    }

    public function getMethod(): string
    {
        return strtoupper($this->request->method());
    }

    public function getQueryString(): ?string
    {
        $query = $this->request->server('QUERY_STRING');

        if (is_string($query)) {
            return $query !== '' ? $query : null;
        }

        return $this->request->getQueryString();
    }

    public function getAllInput(): array
    {
        return $this->request->all();
    }

    public function getQueryInput(): array
    {
        return $this->request->query->all();
    }

    public function getBodyInput(): array
    {
        if ($this->request->isJson()) {
            $json = $this->request->json()->all();

            return is_array($json) ? $json : [];
        }

        return $this->request->request->all();
    }

    public function getRawBody(): string
    {
        return (string) $this->request->getContent();
    }

    public function getHeaders(): array
    {
        return $this->request->headers->all();
    }

    public function getHeader(string $name, string $default = ''): string
    {
        $value = $this->request->header($name, $default);
        if (is_array($value)) {
            $value = implode(', ', array_filter($value, 'is_scalar'));
        }

        return is_scalar($value) ? (string) $value : $default;
    }

    public function getHost(): string
    {
        return strtolower($this->request->getHost());
    }

    public function getInput(string $key, mixed $default = null): mixed
    {
        return $this->request->input($key, $default);
    }

    public function getRequestId(): ?string
    {
        $requestId = $this->request->attributes->get('cybear_request_id');

        return is_string($requestId) && $requestId !== '' ? $requestId : null;
    }

    public function getRouteName(): ?string
    {
        $name = $this->request->route()?->getName();

        return is_string($name) && $name !== '' ? substr($name, 0, 200) : null;
    }

    public function getRouteUri(): ?string
    {
        $uri = $this->request->route()?->uri();

        return is_string($uri) && $uri !== '' ? substr($uri, 0, 500) : null;
    }

    public function getDastCorrelation(): ?array
    {
        $correlation = $this->request->attributes->get('cybear_dast_correlation');

        return is_array($correlation) ? $correlation : null;
    }
}
