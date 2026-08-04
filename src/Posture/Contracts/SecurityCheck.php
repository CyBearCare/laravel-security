<?php

namespace CybearCare\LaravelSecurity\Posture\Contracts;

use CybearCare\LaravelSecurity\Posture\CheckContext;
use CybearCare\LaravelSecurity\Posture\CheckResult;
use CybearCare\LaravelSecurity\Posture\CheckScope;
use CybearCare\LaravelSecurity\Posture\Confidence;
use CybearCare\LaravelSecurity\Posture\Severity;

interface SecurityCheck
{
    public function id(): string;

    public function name(): string;

    public function category(): string;

    public function scope(): CheckScope;

    public function severity(): Severity;

    public function confidence(): Confidence;

    /**
     * @return list<string>
     */
    public function references(): array;

    public function run(CheckContext $context): CheckResult;
}
