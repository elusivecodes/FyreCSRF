<?php
declare(strict_types=1);

namespace Fyre\CSRF\Exceptions;

use
    RuntimeException;

/**
 * CsrfException
 */
class CsrfException extends RuntimeException
{

    public static function forSessionNotActive()
    {
        return new static('Session not active');
    }

    public static function forInvalidToken()
    {
        return new static('CSRF token mismatch', 403);
    }

}
