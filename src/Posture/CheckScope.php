<?php

namespace CybearCare\LaravelSecurity\Posture;

enum CheckScope: string
{
    case Application = 'application';
    case Environment = 'environment';
    case Dependencies = 'dependencies';
    case Runtime = 'runtime';
}
