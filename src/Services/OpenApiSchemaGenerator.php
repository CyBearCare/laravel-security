<?php

namespace CybearCare\LaravelSecurity\Services;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;

class OpenApiSchemaGenerator
{
    protected array $schema;

    public function generate(): array
    {
        $this->schema = [
            'openapi' => '3.0.3',
            'info' => [
                'title' => config('app.name', 'Laravel Application') . ' API',
                'version' => '1.0.0',
                'description' => 'Auto-generated API schema by Cybear Care',
                'x-generated-at' => now()->toISOString(),
                'x-laravel-version' => app()->version(),
                'x-php-version' => PHP_VERSION,
            ],
            'servers' => [
                ['url' => config('app.url', 'http://localhost'), 'description' => config('app.env', 'local')],
            ],
            'paths' => [],
            'components' => [
                'securitySchemes' => $this->buildSecuritySchemes(),
                'schemas' => [],
            ],
            'tags' => [],
        ];

        $this->processRoutes();
        $this->buildTags();

        ksort($this->schema['paths']);

        return $this->schema;
    }

    protected function processRoutes(): void
    {
        foreach (Route::getRoutes() as $route) {
            $uri = '/' . ltrim($route->uri(), '/');
            $methods = array_filter($route->methods(), fn($m) => $m !== 'HEAD');

            foreach ($methods as $method) {
                $operation = $this->buildOperation($route, strtolower($method));
                if ($operation) {
                    $this->schema['paths'][$uri][strtolower($method)] = $operation;
                }
            }
        }
    }

    protected function buildOperation($route, string $method): ?array
    {
        $actionName = $route->getActionName();

        if ($actionName === 'Closure') {
            $name = $route->getName();
            if (!$name) {
                return $this->buildBasicOperation($route, $method);
            }
        }

        $operation = [
            'summary' => $this->generateSummary($route, $method),
            'operationId' => $this->generateOperationId($route, $method),
            'tags' => [$this->getRouteTag($route)],
            'parameters' => $this->buildPathParameters($route),
            'responses' => $this->buildResponses($route, $method),
        ];


        $security = $this->getRouteSecurity($route);
        if (!empty($security)) {
            $operation['security'] = $security;
        }


        $middleware = $route->middleware();
        if (!empty($middleware)) {
            $operation['x-middleware'] = $middleware;
        }


        $operation['x-auth-required'] = $this->routeRequiresAuth($route);
        $operation['x-csrf-protected'] = in_array('web', $route->middleware());


        foreach ($route->middleware() as $mw) {
            if (str_starts_with($mw, 'throttle:')) {
                $operation['x-rate-limit'] = str_replace('throttle:', '', $mw);
                break;
            }
        }


        if (in_array($method, ['post', 'put', 'patch'])) {
            $requestBody = $this->buildRequestBody($route);
            if ($requestBody) {
                $operation['requestBody'] = $requestBody;
            }
        }


        if ($method === 'get') {
            $queryParams = $this->buildQueryParameters($route);
            if (!empty($queryParams)) {
                $operation['parameters'] = array_merge($operation['parameters'], $queryParams);
            }
        }


        if (empty($operation['parameters'])) {
            unset($operation['parameters']);
        }

        return $operation;
    }

    protected function buildBasicOperation($route, string $method): array
    {
        $uri = $route->uri();
        return [
            'summary' => ucfirst($method) . ' ' . $uri,
            'operationId' => $method . '_' . Str::slug($uri, '_'),
            'tags' => [$this->getRouteTag($route)],
            'responses' => $this->buildResponses($route, $method),
        ];
    }

    protected function generateSummary($route, string $method): string
    {

        $name = $route->getName();
        if ($name) {

            $parts = explode('.', $name);
            $action = end($parts);
            $resource = count($parts) > 1 ? $parts[count($parts) - 2] : $parts[0];
            return ucfirst($action) . ' ' . Str::singular(ucfirst($resource));
        }


        $actionName = $route->getActionName();
        if ($actionName !== 'Closure' && str_contains($actionName, '@')) {
            [, $methodName] = explode('@', $actionName);
            $resource = $this->extractResourceFromController($actionName);
            return ucfirst(Str::snake($methodName, ' ')) . ($resource ? ' ' . $resource : '');
        }

        return ucfirst($method) . ' ' . $route->uri();
    }

    protected function generateOperationId($route, string $method): string
    {
        $name = $route->getName();
        if ($name) {
            return Str::camel(str_replace('.', '_', $name));
        }

        $uri = $route->uri();
        return $method . '_' . Str::slug(str_replace(['/', '{', '}'], ['_', '', ''], $uri), '_');
    }

    protected function getRouteTag($route): string
    {

        $name = $route->getName();
        if ($name) {
            $parts = explode('.', $name);
            if (count($parts) >= 2) {
                $tagPart = $parts[0] === 'api' && count($parts) >= 3 ? $parts[1] : $parts[0];
                return ucfirst(Str::plural($tagPart));
            }
        }


        $actionName = $route->getActionName();
        if ($actionName !== 'Closure' && str_contains($actionName, '@')) {
            $resource = $this->extractResourceFromController($actionName);
            if ($resource) {
                return Str::plural($resource);
            }
        }


        $uri = $route->uri();
        $segments = explode('/', trim($uri, '/'));
        $firstSegment = $segments[0] === 'api' && isset($segments[1]) ? $segments[1] : $segments[0];
        return ucfirst($firstSegment);
    }

    protected function extractResourceFromController(string $action): ?string
    {
        if (!str_contains($action, '@')) return null;

        [$controllerClass] = explode('@', $action);
        $shortName = class_basename($controllerClass);


        $resource = str_replace('Controller', '', $shortName);
        return $resource ?: null;
    }

    protected function buildPathParameters($route): array
    {
        $parameters = [];
        $uri = $route->uri();


        preg_match_all('/\{(\w+?)(\?)?\}/', $uri, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $paramName = $match[1];
            $optional = isset($match[2]);
            $paramSchema = $this->inferParameterType($route, $paramName);

            $parameter = [
                'name' => $paramName,
                'in' => 'path',
                'required' => !$optional,
                'schema' => $paramSchema,
            ];


            $description = $this->getParameterDescription($paramName);
            if ($description) {
                $parameter['description'] = $description;
            }

            $parameters[] = $parameter;
        }

        return $parameters;
    }

    protected function inferParameterType($route, string $paramName): array
    {

        $wheres = $route->wheres ?? [];
        if (isset($wheres[$paramName])) {
            $pattern = $wheres[$paramName];
            if ($pattern === '[0-9]+') {
                return ['type' => 'integer'];
            }
            if ($pattern === '[a-zA-Z]+') {
                return ['type' => 'string'];
            }
            return ['type' => 'string', 'pattern' => $pattern];
        }


        if (in_array($paramName, ['id', 'user', 'post', 'comment', 'order'])) {
            return ['type' => 'integer'];
        }
        if (str_ends_with($paramName, '_id')) {
            return ['type' => 'integer'];
        }
        if ($paramName === 'uuid' || str_ends_with($paramName, '_uuid')) {
            return ['type' => 'string', 'format' => 'uuid'];
        }
        if ($paramName === 'slug') {
            return ['type' => 'string'];
        }

        return ['type' => 'string'];
    }

    protected function getParameterDescription(string $paramName): ?string
    {
        $descriptions = [
            'id' => 'Resource ID',
            'uuid' => 'Resource UUID',
            'slug' => 'URL-friendly identifier',
            'token' => 'Authentication or verification token',
        ];

        if (isset($descriptions[$paramName])) {
            return $descriptions[$paramName];
        }

        if (str_ends_with($paramName, '_id')) {
            $resource = ucfirst(str_replace('_id', '', $paramName));
            return $resource . ' ID';
        }

        return null;
    }

    protected function buildRequestBody($route): ?array
    {
        $rules = $this->extractValidationRules($route);

        if (empty($rules)) {
            return null;
        }

        $properties = [];
        $required = [];

        foreach ($rules as $field => $fieldRules) {
            $ruleList = is_string($fieldRules) ? explode('|', $fieldRules) : (array) $fieldRules;
            $ruleStrings = $this->normalizeRules($ruleList);

            $property = $this->rulesToSchema($field, $ruleStrings);
            $properties[$field] = $property;

            if (in_array('required', $ruleStrings)) {
                $required[] = $field;
            }
        }

        if (empty($properties)) {
            return null;
        }

        $schema = [
            'type' => 'object',
            'properties' => $properties,
        ];

        if (!empty($required)) {
            $schema['required'] = $required;
        }


        $hasFile = false;
        foreach ($rules as $field => $fieldRules) {
            $ruleList = is_string($fieldRules) ? explode('|', $fieldRules) : (array) $fieldRules;
            $ruleStrings = $this->normalizeRules($ruleList);
            if (array_intersect($ruleStrings, ['file', 'image', 'mimes', 'mimetypes'])) {
                $hasFile = true;
                break;
            }
        }

        $mediaType = $hasFile ? 'multipart/form-data' : 'application/json';

        return [
            'required' => !empty($required),
            'content' => [
                $mediaType => [
                    'schema' => $schema,
                ],
            ],
        ];
    }

    protected function extractValidationRules($route): array
    {
        $actionName = $route->getActionName();

        if ($actionName === 'Closure' || !str_contains($actionName, '@')) {
            return [];
        }

        [$controllerClass, $methodName] = explode('@', $actionName);

        if (!class_exists($controllerClass)) {
            return [];
        }

        try {
            $reflection = new ReflectionMethod($controllerClass, $methodName);
        } catch (\ReflectionException $e) {
            return [];
        }


        foreach ($reflection->getParameters() as $param) {
            $type = $param->getType();

            if (!$type instanceof ReflectionNamedType || $type->isBuiltin()) {
                continue;
            }

            $typeName = $type->getName();

            if (!class_exists($typeName)) {
                continue;
            }

            try {
                $typeReflection = new ReflectionClass($typeName);

                if ($typeReflection->isSubclassOf(\Illuminate\Foundation\Http\FormRequest::class)) {
                    return $this->getRulesFromFormRequest($typeName);
                }
            } catch (\ReflectionException $e) {
                continue;
            }
        }

        return [];
    }

    protected function getRulesFromFormRequest(string $formRequestClass): array
    {
        try {

            $instance = app()->make($formRequestClass);

            if (method_exists($instance, 'rules')) {
                return $instance->rules();
            }
        } catch (\Exception $e) {

            try {
                $reflection = new ReflectionMethod($formRequestClass, 'rules');

                if ($reflection->getNumberOfRequiredParameters() === 0) {
                    $instance = (new ReflectionClass($formRequestClass))->newInstanceWithoutConstructor();
                    return $reflection->invoke($instance);
                }
            } catch (\Exception $e2) {

            }
        }

        return [];
    }

    protected function normalizeRules(array $rules): array
    {
        $normalized = [];
        foreach ($rules as $rule) {
            if (is_string($rule)) {
                $normalized[] = $rule;
            } elseif (is_object($rule)) {

                $normalized[] = class_basename(get_class($rule));
            }
        }
        return $normalized;
    }

    protected function rulesToSchema(string $field, array $rules): array
    {
        $schema = ['type' => 'string'];


        foreach ($rules as $rule) {
            if ($rule === 'integer' || $rule === 'int') {
                $schema = ['type' => 'integer'];
                break;
            }
            if ($rule === 'numeric' || $rule === 'decimal') {
                $schema = ['type' => 'number'];
                break;
            }
            if ($rule === 'boolean' || $rule === 'bool') {
                $schema = ['type' => 'boolean'];
                break;
            }
            if ($rule === 'array') {
                $schema = ['type' => 'array', 'items' => new \stdClass()];
                break;
            }
            if ($rule === 'json') {
                $schema = ['type' => 'object'];
                break;
            }
            if ($rule === 'file' || $rule === 'image') {
                $schema = ['type' => 'string', 'format' => 'binary'];
                break;
            }
        }


        foreach ($rules as $rule) {
            if (str_starts_with($rule, 'max:')) {
                $val = (int) substr($rule, 4);
                if ($schema['type'] === 'string') {
                    $schema['maxLength'] = $val;
                } elseif (in_array($schema['type'], ['integer', 'number'])) {
                    $schema['maximum'] = $val;
                } elseif ($schema['type'] === 'array') {
                    $schema['maxItems'] = $val;
                }
            }
            if (str_starts_with($rule, 'min:')) {
                $val = (int) substr($rule, 4);
                if ($schema['type'] === 'string') {
                    $schema['minLength'] = $val;
                } elseif (in_array($schema['type'], ['integer', 'number'])) {
                    $schema['minimum'] = $val;
                } elseif ($schema['type'] === 'array') {
                    $schema['minItems'] = $val;
                }
            }
            if (str_starts_with($rule, 'size:')) {
                $val = (int) substr($rule, 5);
                if ($schema['type'] === 'string') {
                    $schema['minLength'] = $val;
                    $schema['maxLength'] = $val;
                }
            }
            if (str_starts_with($rule, 'between:')) {
                $parts = explode(',', substr($rule, 8));
                if (count($parts) === 2) {
                    if ($schema['type'] === 'string') {
                        $schema['minLength'] = (int) $parts[0];
                        $schema['maxLength'] = (int) $parts[1];
                    } elseif (in_array($schema['type'], ['integer', 'number'])) {
                        $schema['minimum'] = (int) $parts[0];
                        $schema['maximum'] = (int) $parts[1];
                    }
                }
            }
            if (str_starts_with($rule, 'in:')) {
                $schema['enum'] = explode(',', substr($rule, 3));
            }
            if (str_starts_with($rule, 'regex:')) {
                $schema['pattern'] = trim(substr($rule, 6), '/');
            }
            if ($rule === 'email') {
                $schema['format'] = 'email';
            }
            if ($rule === 'url' || $rule === 'active_url') {
                $schema['format'] = 'uri';
            }
            if ($rule === 'ip' || $rule === 'ipv4') {
                $schema['format'] = 'ipv4';
            }
            if ($rule === 'ipv6') {
                $schema['format'] = 'ipv6';
            }
            if ($rule === 'uuid') {
                $schema['format'] = 'uuid';
            }
            if ($rule === 'date' || $rule === 'date_format') {
                $schema['format'] = 'date';
            }
            if (str_starts_with($rule, 'date_format:')) {
                $format = substr($rule, 12);
                if (str_contains($format, 'H') || str_contains($format, 'h')) {
                    $schema['format'] = 'date-time';
                } else {
                    $schema['format'] = 'date';
                }
            }
            if ($rule === 'nullable') {
                $schema['nullable'] = true;
            }
            if ($rule === 'confirmed') {
                $schema['x-confirmed'] = true;
            }
            if ($rule === 'password') {
                $schema['format'] = 'password';
            }
        }


        $description = $this->fieldNameToDescription($field);
        if ($description) {
            $schema['description'] = $description;
        }

        return $schema;
    }

    protected function fieldNameToDescription(string $field): ?string
    {

        $name = str_replace(['.', '_'], ' ', $field);
        $name = ucfirst(trim($name));


        if (strlen($name) <= 3) {
            return null;
        }

        return $name;
    }

    protected function buildQueryParameters($route): array
    {
        $rules = $this->extractValidationRules($route);
        $parameters = [];


        foreach ($rules as $field => $fieldRules) {

            if (str_contains($field, '.') || str_contains($field, '*')) {
                continue;
            }

            $ruleList = is_string($fieldRules) ? explode('|', $fieldRules) : (array) $fieldRules;
            $ruleStrings = $this->normalizeRules($ruleList);

            $parameter = [
                'name' => $field,
                'in' => 'query',
                'required' => in_array('required', $ruleStrings),
                'schema' => $this->rulesToSchema($field, $ruleStrings),
            ];

            $parameters[] = $parameter;
        }

        return $parameters;
    }

    protected function buildResponses($route, string $method): array
    {
        $responses = [];


        $successCode = match ($method) {
            'post' => '201',
            'delete' => '204',
            default => '200',
        };

        $responses[$successCode] = [
            'description' => match ($successCode) {
                '201' => 'Resource created successfully',
                '204' => 'Resource deleted successfully',
                default => 'Successful response',
            },
        ];


        if ($successCode !== '204') {
            $responses[$successCode]['content'] = [
                'application/json' => [
                    'schema' => [
                        'type' => 'object',
                    ],
                ],
            ];
        }


        if ($this->routeRequiresAuth($route)) {
            $responses['401'] = [
                'description' => 'Unauthenticated',
            ];
            $responses['403'] = [
                'description' => 'Forbidden',
            ];
        }


        if (in_array($method, ['post', 'put', 'patch'])) {
            $responses['422'] = [
                'description' => 'Validation error',
                'content' => [
                    'application/json' => [
                        'schema' => [
                            'type' => 'object',
                            'properties' => [
                                'message' => ['type' => 'string'],
                                'errors' => ['type' => 'object'],
                            ],
                        ],
                    ],
                ],
            ];
        }

        return $responses;
    }

    protected function routeRequiresAuth($route): bool
    {
        $middleware = $route->middleware();

        foreach ($middleware as $mw) {
            if ($mw === 'auth' || str_starts_with($mw, 'auth:')) {
                return true;
            }
        }

        return false;
    }

    protected function getRouteSecurity($route): array
    {
        $middleware = $route->middleware();
        $security = [];

        foreach ($middleware as $mw) {
            if ($mw === 'auth:sanctum') {
                $security[] = ['bearerAuth' => []];
                break;
            }
            if ($mw === 'auth:api' || str_starts_with($mw, 'auth:')) {
                $security[] = ['bearerAuth' => []];
                break;
            }
            if ($mw === 'auth') {
                $security[] = ['cookieAuth' => []];
                break;
            }
        }

        return $security;
    }

    protected function buildSecuritySchemes(): array
    {
        $schemes = [];


        $guards = config('auth.guards', []);

        if (isset($guards['sanctum']) || isset($guards['api'])) {
            $schemes['bearerAuth'] = [
                'type' => 'http',
                'scheme' => 'bearer',
                'bearerFormat' => isset($guards['sanctum']) ? 'Sanctum' : 'JWT',
            ];
        }

        if (isset($guards['web'])) {
            $schemes['cookieAuth'] = [
                'type' => 'apiKey',
                'in' => 'cookie',
                'name' => config('session.cookie', 'laravel_session'),
            ];
        }


        $schemes['csrfToken'] = [
            'type' => 'apiKey',
            'in' => 'header',
            'name' => 'X-CSRF-TOKEN',
            'description' => 'CSRF protection token',
        ];

        return $schemes;
    }

    protected function buildTags(): void
    {
        $tags = [];

        foreach ($this->schema['paths'] as $path => $methods) {
            foreach ($methods as $method => $operation) {
                if (isset($operation['tags'])) {
                    foreach ($operation['tags'] as $tag) {
                        $tags[$tag] = true;
                    }
                }
            }
        }

        ksort($tags);
        $this->schema['tags'] = array_map(
            fn($name) => ['name' => $name],
            array_keys($tags)
        );
    }


    public function toJson(int $options = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->generate(), $options);
    }


    public function toYaml(): string
    {
        if (function_exists('yaml_emit')) {
            return yaml_emit($this->generate());
        }


        return json_encode($this->generate(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }


    public function getStatistics(): array
    {
        $routes = Route::getRoutes();
        $stats = [
            'total_routes' => 0,
            'api_routes' => 0,
            'web_routes' => 0,
            'auth_required' => 0,
            'with_validation' => 0,
            'methods' => [],
        ];

        foreach ($routes as $route) {
            $stats['total_routes']++;

            $middleware = $route->middleware();
            if (in_array('api', $middleware)) {
                $stats['api_routes']++;
            } elseif (in_array('web', $middleware)) {
                $stats['web_routes']++;
            }

            if ($this->routeRequiresAuth($route)) {
                $stats['auth_required']++;
            }

            $rules = $this->extractValidationRules($route);
            if (!empty($rules)) {
                $stats['with_validation']++;
            }

            foreach ($route->methods() as $method) {
                if ($method !== 'HEAD') {
                    $stats['methods'][$method] = ($stats['methods'][$method] ?? 0) + 1;
                }
            }
        }

        return $stats;
    }
}
