<?php

namespace CybearCare\LaravelSecurity\Posture;

use CybearCare\LaravelSecurity\Posture\Contracts\SecurityCheck;
use InvalidArgumentException;

final class CheckRegistry
{
    /** @var array<string, SecurityCheck> */
    private array $checks = [];

    /**
     * @param iterable<SecurityCheck> $checks
     */
    public function __construct(iterable $checks = [])
    {
        foreach ($checks as $check) {
            $this->add($check);
        }
    }

    public function add(SecurityCheck $check): self
    {
        $id = $check->id();

        if (!preg_match('/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/', $id)) {
            throw new InvalidArgumentException("Security check ID [{$id}] is not stable or machine-safe.");
        }

        if (isset($this->checks[$id])) {
            throw new InvalidArgumentException("Security check [{$id}] is already registered.");
        }

        $this->checks[$id] = $check;

        return $this;
    }

    /**
     * @return list<SecurityCheck>
     */
    public function all(): array
    {
        $checks = $this->checks;
        ksort($checks);

        return array_values($checks);
    }

    /**
     * @param list<string> $ids
     * @param list<string> $categories
     * @param list<string> $excludedIds
     * @return list<SecurityCheck>
     */
    public function select(
        array $ids = [],
        array $categories = [],
        Severity $minimumSeverity = Severity::Info,
        array $excludedIds = [],
    ): array {
        $ids = array_values(array_unique($ids));
        $categories = array_values(array_unique($categories));
        $excluded = array_fill_keys($excludedIds, true);

        return array_values(array_filter(
            $this->all(),
            static fn (SecurityCheck $check): bool =>
                !isset($excluded[$check->id()])
                && ($ids === [] || in_array($check->id(), $ids, true))
                && ($categories === [] || in_array($check->category(), $categories, true))
                && $check->severity()->meets($minimumSeverity),
        ));
    }

    /**
     * @return list<string>
     */
    public function ids(): array
    {
        return array_map(static fn (SecurityCheck $check): string => $check->id(), $this->all());
    }

    /**
     * @return list<string>
     */
    public function categories(): array
    {
        $categories = array_values(array_unique(array_map(
            static fn (SecurityCheck $check): string => $check->category(),
            $this->all(),
        )));
        sort($categories);

        return $categories;
    }
}
