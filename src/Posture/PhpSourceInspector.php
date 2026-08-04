<?php

namespace CybearCare\LaravelSecurity\Posture;

use Composer\Autoload\ClassLoader;
use Illuminate\Routing\Route;
use Throwable;

final class PhpSourceInspector
{
    private const MAX_METHOD_CACHE_BYTES = 16 * 1024 * 1024;

    private const BUILTIN_TYPES = [
        'array', 'bool', 'callable', 'false', 'float', 'int', 'iterable',
        'mixed', 'never', 'null', 'object', 'parent', 'self', 'static',
        'string', 'true', 'void',
    ];

    /** @var array<string, SourceMethod> */
    private array $methodCache = [];

    private int $methodCacheBytes = 0;

    /** @var array<string, array{namespace: string, imports: array<string, string>, parent: string|null}|null> */
    private array $classMetadataCache = [];

    /** @var array<string, string|null> */
    private array $classFileCache = [];

    public function routeAction(CheckContext $context, Route $route): SourceMethod
    {
        $action = $route->getActionName();
        if ($action === 'Closure') {
            return new SourceMethod($action, null, null, false, 'unsupported_route_action', []);
        }

        if (str_contains($action, '@')) {
            [$class, $method] = explode('@', $action, 2);
        } else {
            $class = $action;
            $method = '__invoke';
            $action .= '@__invoke';
        }

        return $this->method($context, $class, $method, $action);
    }

    /**
     * @return list<SourceMethod>
     */
    public function relatedMethods(
        CheckContext $context,
        SourceMethod $root,
        int $maximumDepth = 2,
    ): array {
        if (!$root->available || $root->className === null) {
            return [$root];
        }

        $methods = [$root];
        $seen = [strtolower((string) $root->methodName) => true];
        $frontier = [[$root, 0]];

        while ($frontier !== []) {
            [$current, $depth] = array_shift($frontier);
            if ($depth >= max(0, min(3, $maximumDepth))) {
                continue;
            }

            foreach ($current->calledMethodNames() as $called) {
                $key = strtolower($called);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;

                $method = $this->method($context, $root->className, $called);
                if (!$method->available) {
                    continue;
                }

                $methods[] = $method;
                $frontier[] = [$method, $depth + 1];
            }
        }

        return $methods;
    }

    public function method(
        CheckContext $context,
        string $class,
        string $method,
        ?string $action = null,
    ): SourceMethod {
        $class = ltrim(trim($class), '\\');
        $method = trim($method);
        $action ??= "{$class}@{$method}";
        $maximumBytes = $this->maximumBytes($context);
        $cacheKey = "{$context->basePath()}|{$maximumBytes}|{$class}@{$method}";

        if (isset($this->methodCache[$cacheKey])) {
            return $this->methodCache[$cacheKey];
        }

        if ($class === '' || $method === '') {
            return $this->remember($cacheKey, new SourceMethod(
                $action,
                $class !== '' ? $class : null,
                $method !== '' ? $method : null,
                false,
                'invalid_action',
                [],
            ));
        }

        $file = $this->classFile($class, $context->basePath());
        if ($file === null) {
            return $this->remember($cacheKey, new SourceMethod(
                $action,
                $class,
                $method,
                false,
                'source_not_local',
                [],
            ));
        }

        $source = $this->readBounded($file, $maximumBytes);
        if ($source === null) {
            return $this->remember($cacheKey, new SourceMethod(
                $action,
                $class,
                $method,
                false,
                'source_unreadable_or_too_large',
                [],
            ));
        }

        $parts = $this->methodParts($source, $method);
        if ($parts === null) {
            return $this->remember($cacheKey, new SourceMethod(
                $action,
                $class,
                $method,
                false,
                'method_not_declared_in_source',
                [],
            ));
        }

        [$namespace, $imports] = $this->namespaceAndImports($source);

        return $this->remember($cacheKey, new SourceMethod(
            action: $action,
            className: $class,
            methodName: $method,
            available: true,
            unavailableReason: null,
            parameterTypes: $this->parameterTypes($parts['signature'], $namespace, $imports),
            parameterVariables: $this->parameterVariables($parts['signature'], $namespace, $imports),
            relativeFile: $this->relativePath($file, $context->basePath()),
            startLine: $parts['start_line'],
            source: $parts['source'],
        ));
    }

    /**
     * @return list<string>
     */
    public function formRequestTypes(CheckContext $context, SourceMethod $method): array
    {
        $types = [];

        foreach ($method->parameterTypes as $type) {
            if ($this->isFormRequest($context, $type)) {
                $types[] = $type;
            }
        }

        return array_values(array_unique($types));
    }

    public function isFormRequest(CheckContext $context, string $class): bool
    {
        return $this->isLocalSubclassOf(
            $context,
            $class,
            'Illuminate\\Foundation\\Http\\FormRequest',
        );
    }

    /**
     * @return list<string>
     */
    public function requestVariableNames(CheckContext $context, SourceMethod $method): array
    {
        $variables = [];

        foreach ($method->parameterVariables as $variable => $types) {
            foreach ($types as $type) {
                if ($type === 'Illuminate\\Http\\Request'
                    || $this->isLocalSubclassOf($context, $type, 'Illuminate\\Http\\Request')) {
                    $variables[] = $variable;
                    break;
                }
            }
        }

        return array_values(array_unique($variables));
    }

    private function isLocalSubclassOf(
        CheckContext $context,
        string $class,
        string $target,
    ): bool {
        $current = ltrim($class, '\\');
        $seen = [];

        for ($depth = 0; $depth < 8; $depth++) {
            if (strcasecmp($current, $target) === 0) {
                return true;
            }

            $normalized = strtolower($current);
            if (isset($seen[$normalized])) {
                return false;
            }
            $seen[$normalized] = true;

            $metadata = $this->classMetadata($context, $current);
            if ($metadata === null || $metadata['parent'] === null) {
                return false;
            }

            $current = $this->resolveType(
                $metadata['parent'],
                $metadata['namespace'],
                $metadata['imports'],
            );
        }

        return false;
    }

    private function remember(string $key, SourceMethod $method): SourceMethod
    {
        $bytes = $method->sourceByteLength();

        while ($this->methodCache !== []
            && (count($this->methodCache) >= 1000
                || $this->methodCacheBytes + $bytes > self::MAX_METHOD_CACHE_BYTES)) {
            $evicted = array_shift($this->methodCache);
            if ($evicted instanceof SourceMethod) {
                $this->methodCacheBytes -= $evicted->sourceByteLength();
            }
        }

        if ($bytes > self::MAX_METHOD_CACHE_BYTES) {
            return $method;
        }

        $this->methodCache[$key] = $method;
        $this->methodCacheBytes += $bytes;

        return $method;
    }

    private function maximumBytes(CheckContext $context): int
    {
        $configured = $context->config('cybear.posture.max_source_file_bytes', 524288);
        $bytes = is_numeric($configured) ? (int) $configured : 524288;

        return max(16384, min(5 * 1024 * 1024, $bytes));
    }

    private function classFile(string $class, string $basePath): ?string
    {
        $cacheKey = "{$basePath}|{$class}";
        if (array_key_exists($cacheKey, $this->classFileCache)) {
            return $this->classFileCache[$cacheKey];
        }

        $candidate = null;

        try {
            if (class_exists($class, false)
                || interface_exists($class, false)
                || trait_exists($class, false)
                || (function_exists('enum_exists') && enum_exists($class, false))) {
                $reflection = new \ReflectionClass($class);
                $file = $reflection->getFileName();
                $candidate = is_string($file) ? $file : null;
            }
        } catch (Throwable) {
            $candidate = null;
        }

        if ($candidate === null) {
            foreach (spl_autoload_functions() ?: [] as $autoload) {
                if (!is_array($autoload)
                    || !($autoload[0] ?? null) instanceof ClassLoader) {
                    continue;
                }

                try {
                    $file = $autoload[0]->findFile($class);
                    if (is_string($file) && $file !== '') {
                        $candidate = $file;
                        break;
                    }
                } catch (Throwable) {
                    // A broken autoloader must not abort the rest of the scan.
                }
            }
        }

        if ($candidate === null) {
            return $this->classFileCache[$cacheKey] = null;
        }

        $real = realpath($candidate);
        $base = realpath($basePath);
        $vendor = realpath(rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . 'vendor');

        if (!is_string($real)
            || !is_string($base)
            || !is_file($real)
            || !PathInspector::isWithin($real, $base)
            || (is_string($vendor) && PathInspector::isWithin($real, $vendor))) {
            return $this->classFileCache[$cacheKey] = null;
        }

        if (count($this->classFileCache) >= 2000) {
            array_shift($this->classFileCache);
        }

        return $this->classFileCache[$cacheKey] = $real;
    }

    private function readBounded(string $file, int $maximumBytes): ?string
    {
        $size = @filesize($file);
        if (!is_int($size) || $size < 1 || $size > $maximumBytes) {
            return null;
        }

        $handle = @fopen($file, 'rb');
        if (!is_resource($handle)) {
            return null;
        }

        try {
            $source = stream_get_contents($handle, $maximumBytes + 1);
        } finally {
            fclose($handle);
        }

        return is_string($source) && strlen($source) <= $maximumBytes ? $source : null;
    }

    /**
     * @return array{signature: string, source: string, start_line: int}|null
     */
    private function methodParts(string $source, string $method): ?array
    {
        try {
            $tokens = token_get_all($source);
        } catch (Throwable) {
            return null;
        }

        $count = count($tokens);
        for ($index = 0; $index < $count; $index++) {
            if (!is_array($tokens[$index]) || $tokens[$index][0] !== T_FUNCTION) {
                continue;
            }

            $nameIndex = $index + 1;
            while ($nameIndex < $count && $this->isIgnorableFunctionNameToken($tokens[$nameIndex])) {
                $nameIndex++;
            }

            if ($nameIndex >= $count
                || !is_array($tokens[$nameIndex])
                || $tokens[$nameIndex][0] !== T_STRING
                || strcasecmp($tokens[$nameIndex][1], $method) !== 0) {
                continue;
            }

            $openParenthesis = $this->findCharacter($tokens, $nameIndex + 1, '(');
            if ($openParenthesis === null) {
                return null;
            }

            $closeParenthesis = $this->matchingCharacter($tokens, $openParenthesis, '(', ')');
            if ($closeParenthesis === null) {
                return null;
            }

            $bodyStart = $this->findBodyStart($tokens, $closeParenthesis + 1);
            if ($bodyStart === null || $tokens[$bodyStart] !== '{') {
                return null;
            }

            $bodyEnd = $this->matchingCharacter($tokens, $bodyStart, '{', '}');
            if ($bodyEnd === null) {
                return null;
            }

            return [
                'signature' => $this->tokensToString($tokens, $index, $closeParenthesis),
                'source' => $this->tokensToString($tokens, $index, $bodyEnd),
                'start_line' => is_array($tokens[$index]) ? $tokens[$index][2] : 1,
            ];
        }

        return null;
    }

    private function isIgnorableFunctionNameToken(mixed $token): bool
    {
        if (is_string($token)) {
            return $token === '&' || trim($token) === '';
        }

        return in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)
            || (defined('T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG')
                && $token[0] === constant('T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG'));
    }

    /**
     * @param array<int, array{int, string, int}|string> $tokens
     */
    private function findCharacter(array $tokens, int $start, string $character): ?int
    {
        $count = count($tokens);
        for ($index = $start; $index < $count; $index++) {
            if ($tokens[$index] === $character) {
                return $index;
            }

            if ($tokens[$index] === ';' || $tokens[$index] === '{') {
                return null;
            }
        }

        return null;
    }

    /**
     * @param array<int, array{int, string, int}|string> $tokens
     */
    private function matchingCharacter(
        array $tokens,
        int $start,
        string $open,
        string $close,
    ): ?int {
        $depth = 0;
        $count = count($tokens);

        for ($index = $start; $index < $count; $index++) {
            if ($tokens[$index] === $open) {
                $depth++;
            } elseif ($tokens[$index] === $close && --$depth === 0) {
                return $index;
            }
        }

        return null;
    }

    /**
     * @param array<int, array{int, string, int}|string> $tokens
     */
    private function findBodyStart(array $tokens, int $start): ?int
    {
        $count = count($tokens);
        for ($index = $start; $index < $count; $index++) {
            if ($tokens[$index] === '{' || $tokens[$index] === ';') {
                return $index;
            }
        }

        return null;
    }

    /**
     * @param array<int, array{int, string, int}|string> $tokens
     */
    private function tokensToString(array $tokens, int $start, int $end): string
    {
        $source = '';
        for ($index = $start; $index <= $end; $index++) {
            $source .= is_array($tokens[$index]) ? $tokens[$index][1] : $tokens[$index];
        }

        return $source;
    }

    /**
     * @return array{string, array<string, string>}
     */
    private function namespaceAndImports(string $source): array
    {
        $namespace = '';
        if (preg_match('/\bnamespace\s+([^;{]+)[;{]/i', $source, $match) === 1) {
            $namespace = trim($match[1]);
        }

        $prefix = preg_split('/\b(?:abstract\s+|final\s+|readonly\s+)*class\s+/i', $source, 2)[0]
            ?? $source;
        $imports = [];

        if (preg_match_all(
            '/^\s*use\s+(?!function\b|const\b)([^;{}]+);/mi',
            $prefix,
            $matches,
        ) === false) {
            return [$namespace, $imports];
        }

        foreach ($matches[1] as $statement) {
            foreach (explode(',', $statement) as $import) {
                $import = trim($import);
                if ($import === '' || str_contains($import, '{')) {
                    continue;
                }

                $parts = preg_split('/\s+as\s+/i', $import);
                $qualified = ltrim(trim($parts[0]), '\\');
                $alias = isset($parts[1])
                    ? trim($parts[1])
                    : basename(str_replace('\\', '/', $qualified));

                if ($qualified !== '' && $alias !== '') {
                    $imports[strtolower($alias)] = $qualified;
                }
            }
        }

        return [$namespace, $imports];
    }

    /**
     * @param array<string, string> $imports
     * @return list<string>
     */
    private function parameterTypes(string $signature, string $namespace, array $imports): array
    {
        $identifier = '[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff\\\\]*';
        $pattern = '/((?:\\\\?' . $identifier . ')(?:\s*[|&]\s*\\\\?' . $identifier . ')*)\s+\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*/u';

        if (preg_match_all($pattern, $signature, $matches) === false) {
            return [];
        }

        $types = [];
        foreach ($matches[1] as $declaration) {
            foreach (preg_split('/[|&]/', $declaration) ?: [] as $type) {
                $type = ltrim(trim($type), '?');
                if ($type === '' || in_array(strtolower($type), self::BUILTIN_TYPES, true)) {
                    continue;
                }

                $types[] = $this->resolveType($type, $namespace, $imports);
            }
        }

        return array_values(array_unique($types));
    }

    /**
     * @param array<string, string> $imports
     * @return array<string, list<string>>
     */
    private function parameterVariables(string $signature, string $namespace, array $imports): array
    {
        $identifier = '[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff\\\\]*';
        $pattern = '/((?:\\\\?' . $identifier . ')(?:\s*[|&]\s*\\\\?' . $identifier . ')*)\s+(\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)/u';

        if (preg_match_all($pattern, $signature, $matches, PREG_SET_ORDER) === false) {
            return [];
        }

        $variables = [];
        foreach ($matches as $match) {
            $types = [];
            foreach (preg_split('/[|&]/', $match[1]) ?: [] as $type) {
                $type = ltrim(trim($type), '?');
                if ($type === '' || in_array(strtolower($type), self::BUILTIN_TYPES, true)) {
                    continue;
                }
                $types[] = $this->resolveType($type, $namespace, $imports);
            }

            if ($types !== []) {
                $variables[$match[2]] = array_values(array_unique($types));
            }
        }

        return $variables;
    }

    /**
     * @param array<string, string> $imports
     */
    private function resolveType(string $type, string $namespace, array $imports): string
    {
        if (str_starts_with($type, '\\')) {
            return ltrim($type, '\\');
        }

        $segments = explode('\\', $type);
        $alias = strtolower($segments[0]);
        if (isset($imports[$alias])) {
            array_shift($segments);

            return $imports[$alias] . ($segments !== [] ? '\\' . implode('\\', $segments) : '');
        }

        return $namespace !== '' ? trim($namespace, '\\') . '\\' . $type : $type;
    }

    /**
     * @return array{namespace: string, imports: array<string, string>, parent: string|null}|null
     */
    private function classMetadata(CheckContext $context, string $class): ?array
    {
        $cacheKey = "{$context->basePath()}|{$class}";
        if (array_key_exists($cacheKey, $this->classMetadataCache)) {
            return $this->classMetadataCache[$cacheKey];
        }

        $file = $this->classFile($class, $context->basePath());
        $source = $file !== null ? $this->readBounded($file, $this->maximumBytes($context)) : null;
        if ($source === null) {
            return $this->classMetadataCache[$cacheKey] = null;
        }

        [$namespace, $imports] = $this->namespaceAndImports($source);
        $shortName = basename(str_replace('\\', '/', $class));
        $pattern = '/\bclass\s+' . preg_quote($shortName, '/') . '\s+(?:[^{]*?\s)?extends\s+([\\\\A-Za-z_\x80-\xff][\\\\A-Za-z0-9_\x80-\xff]*)/iu';
        $parent = preg_match($pattern, $source, $match) === 1 ? trim($match[1]) : null;

        return $this->classMetadataCache[$cacheKey] = [
            'namespace' => $namespace,
            'imports' => $imports,
            'parent' => $parent,
        ];
    }

    private function relativePath(string $file, string $basePath): string
    {
        $base = rtrim(str_replace('\\', '/', (string) realpath($basePath)), '/');
        $real = str_replace('\\', '/', (string) realpath($file));

        if ($base !== '' && str_starts_with($real, $base . '/')) {
            return substr($real, strlen($base) + 1);
        }

        return basename($real);
    }
}
