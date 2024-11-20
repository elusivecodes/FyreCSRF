<?php
declare(strict_types=1);

namespace Fyre\Security\Exceptions;

use RuntimeException;

/**
 * CsrfException
 */
class CsrfException extends RuntimeException
{
    public static function forCsrfAlreadySet(): static
    {
        return new static('CSRF parameter has already been set');
    }

    public static function forInvalidToken(): static
    {
        return new static('CSRF token mismatch', 403);
    }
}
