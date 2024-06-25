<?php
declare(strict_types=1);

namespace Fyre\Security\Exceptions;

use RuntimeException;

/**
 * CsrfException
 */
class CsrfException extends RuntimeException
{
    public static function forInvalidToken(): static
    {
        return new static('CSRF token mismatch', 403);
    }

    public static function forSessionNotActive(): static
    {
        return new static('Session not active');
    }
}
