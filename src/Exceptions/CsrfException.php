<?php
declare(strict_types=1);

namespace Fyre\CSRF\Exceptions;

use
    RunTimeException;

/**
 * CsrfException
 */
class CsrfException extends RunTimeException
{

    public static function forSessionNotActive()
    {
        return new static('Session not active');
    }

    public static function forInvalidToken()
    {
        return new static('CSRF token mismatch');
    }

}
