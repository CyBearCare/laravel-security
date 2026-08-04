<?php

namespace CybearCare\LaravelSecurity\Posture;

enum Confidence: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
}
