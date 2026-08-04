<?php

namespace CybearCare\LaravelSecurity\Posture;

final readonly class SourceMethod
{
    /**
     * @param list<string> $parameterTypes
     * @param array<string, list<string>> $parameterVariables
     */
    public function __construct(
        public string $action,
        public ?string $className,
        public ?string $methodName,
        public bool $available,
        public ?string $unavailableReason,
        public array $parameterTypes,
        public array $parameterVariables = [],
        public ?string $relativeFile = null,
        public ?int $startLine = null,
        private string $source = '',
    ) {
    }

    /**
     * @return array{file: string, line: int}|null
     */
    public function location(): ?array
    {
        if ($this->relativeFile === null || $this->startLine === null) {
            return null;
        }

        return [
            'file' => $this->relativeFile,
            'line' => $this->startLine,
        ];
    }

    /**
     * @param array<string, string> $patterns
     * @return list<string>
     */
    public function matchingSignals(array $patterns): array
    {
        if (!$this->available || $this->source === '') {
            return [];
        }

        $matches = [];
        foreach ($patterns as $name => $pattern) {
            if (@preg_match($pattern, $this->source) === 1) {
                $matches[] = $name;
            }
        }

        return $matches;
    }

    /**
     * @param array<string, string> $patterns
     */
    public function hasAnySignal(array $patterns): bool
    {
        return $this->matchingSignals($patterns) !== [];
    }

    /**
     * @return list<string>
     */
    public function calledMethodNames(): array
    {
        if (!$this->available || $this->source === '') {
            return [];
        }

        $matches = [];
        preg_match_all(
            '/(?:\$this\s*->|self\s*::|static\s*::)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/i',
            $this->source,
            $matches,
        );

        return array_values(array_unique(array_filter(
            $matches[1] ?? [],
            fn (string $name): bool => strcasecmp($name, (string) $this->methodName) !== 0,
        )));
    }

    /**
     * @param array<string, string> $sourcePatterns
     * @param array<string, string> $sinkPatterns
     * @return list<string>
     */
    public function matchingTaintedVariableFlows(
        array $sourcePatterns,
        array $sinkPatterns,
    ): array {
        if (!$this->available || $this->source === '') {
            return [];
        }

        $tainted = [];
        $matches = [];
        $statements = preg_split('/;(?=(?:[^\'"]|\'[^\']*\'|"[^"]*")*$)/s', $this->source) ?: [];

        foreach ($statements as $statement) {
            if (preg_match(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/s',
                trim($statement),
                $assignment,
            ) === 1) {
                $variable = '$' . $assignment[1];
                $expression = trim($assignment[2]);
                $sourceName = null;

                foreach ($sourcePatterns as $name => $pattern) {
                    if (@preg_match($pattern, $expression) === 1) {
                        $sourceName = $name;
                        break;
                    }
                }

                if ($sourceName !== null) {
                    $tainted[$variable] = $sourceName;
                } elseif (preg_match('/^\$([A-Za-z_][A-Za-z0-9_]*)$/', $expression, $alias) === 1
                    && isset($tainted['$' . $alias[1]])) {
                    $tainted[$variable] = $tainted['$' . $alias[1]];
                } else {
                    unset($tainted[$variable]);
                }
            }

            foreach ($tainted as $variable => $sourceName) {
                foreach ($sinkPatterns as $sinkName => $template) {
                    $pattern = str_replace(
                        '{{variable}}',
                        preg_quote($variable, '/'),
                        $template,
                    );
                    if (@preg_match($pattern, $statement) === 1) {
                        $matches[] = "{$sourceName}_to_{$sinkName}";
                    }
                }
            }
        }

        return array_values(array_unique($matches));
    }

    /**
     * @return list<string>
     */
    public function requestFileFields(): array
    {
        if (!$this->available || $this->source === '') {
            return [];
        }

        preg_match_all(
            '/->\s*(?:file|hasFile)\s*\(\s*[\'"]([^\'"]{1,200})[\'"]\s*\)/i',
            $this->source,
            $matches,
        );

        return array_values(array_unique($matches[1] ?? []));
    }

    /**
     * @param array<string, string> $patterns
     * @return list<string>
     */
    public function matchingValidationSignalsForField(string $field, array $patterns): array
    {
        if (!$this->available || $this->source === '' || $field === '') {
            return [];
        }

        $fieldPattern = preg_quote($field, '/');
        if (preg_match(
            '/[\'"]' . $fieldPattern . '[\'"]\s*=>\s*(.{1,3000}?)(?=,\s*[\'"][^\'"]+[\'"]\s*=>|\r?\n\s*\]|\r?\n)/is',
            $this->source,
            $match,
        ) !== 1) {
            return [];
        }

        $signals = [];
        foreach ($patterns as $name => $pattern) {
            if (@preg_match($pattern, $match[1]) === 1) {
                $signals[] = $name;
            }
        }

        return $signals;
    }

    public function sourceByteLength(): int
    {
        return strlen($this->source);
    }
}
