<?php
declare(strict_types=1);

namespace Fyre\CSRF\Exceptions;

use
    Fyre\Error\Exceptions\ForbiddenException;

/**
 * CsrfException
 */
class CsrfException extends ForbiddenException
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
