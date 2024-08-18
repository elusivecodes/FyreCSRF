<?php
declare(strict_types=1);

namespace Fyre\Security;

use Closure;
use Fyre\Security\Exceptions\CsrfException;
use Fyre\Server\ServerRequest;

use function call_user_func;
use function hash;
use function in_array;
use function password_hash;
use function password_verify;
use function random_bytes;
use function session_status;

use const PASSWORD_DEFAULT;
use const PHP_SESSION_ACTIVE;

/**
 * CsrfProtection
 */
abstract class CsrfProtection
{
    protected const CHECK_METHODS = [
        'delete',
        'patch',
        'post',
        'put',
    ];

    protected static bool $enabled = false;

    protected static string $field = 'csrf_token';

    protected static string $header = 'Csrf-Token';

    protected static string $key = '_csrfToken';

    protected static Closure|null $skipCheck = null;

    /**
     * Check CSRF token.
     *
     * @param ServerRequest $request The ServerRequest.
     *
     * @throws CsrfException if the token is invalid.
     */
    public static function checkToken(ServerRequest $request): void
    {
        $userToken = $_POST[static::$field] ?? $request->getHeaderValue(static::$header);

        unset($_POST[static::$field]);

        if (!in_array($request->getMethod(), static::CHECK_METHODS)) {
            return;
        }

        if (static::$skipCheck && call_user_func(static::$skipCheck, $request) === true) {
            return;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw CsrfException::forSessionNotActive();
        }

        $token = static::getToken();

        if (!$userToken || !password_verify($token, $userToken)) {
            throw CsrfException::forInvalidToken();
        }
    }

    /**
     * Disable the CSRF protection.
     */
    public static function disable(): void
    {
        static::$enabled = false;
    }

    /**
     * Enable the CSRF protection.
     */
    public static function enable(): void
    {
        static::$enabled = true;
    }

    /**
     * Get the CSRF token field name.
     *
     * @return string The CSRF token field name.
     */
    public static function getField(): string
    {
        return static::$field;
    }

    /**
     * Get the CSRF token header name.
     *
     * @return string The CSRF token header name.
     */
    public static function getHeader(): string
    {
        return static::$header;
    }

    /**
     * Get the CSRF session key.
     *
     * @return string The CSRF session key.
     */
    public static function getKey(): string
    {
        return static::$key;
    }

    /**
     * Get the CSRF token.
     *
     * @return string The CSRF token.
     */
    public static function getToken(): string
    {
        return $_SESSION[static::$key] ??= static::generateToken();
    }

    /**
     * Get the CSRF token hash.
     *
     * @return string The CSRF token hash.
     */
    public static function getTokenHash(): string
    {
        return password_hash(static::getToken(), PASSWORD_DEFAULT);
    }

    /**
     * Determine if the CSRF protection is enabled.
     *
     * @return bool TRUE if the CSRF protection is enabled, otherwise FALSE.
     */
    public static function isEnabled(): bool
    {
        return static::$enabled;
    }

    /**
     * Set the CSRF token field name.
     *
     * @param string $field The CSRF token field name.
     */
    public static function setField(string $field): void
    {
        static::$field = $field;
    }

    /**
     * Set the CSRF token header.
     *
     * @param string $header The CSRF token header.
     */
    public static function setHeader(string $header): void
    {
        static::$header = $header;
    }

    /**
     * Set the CSRF session key.
     *
     * @param string $key The CSRF session key.
     */
    public static function setKey(string $key): void
    {
        static::$key = $key;
    }

    /**
     * Set the skip check callback.
     *
     * @param Closure|null $skipCheck The skip check callback.
     */
    public static function skipCheckCallback(Closure|null $skipCheck): void
    {
        static::$skipCheck = $skipCheck;
    }

    /**
     * Generate a CSRF token.
     *
     * @return string The CSRF token.
     */
    protected static function generateToken(): string
    {
        return hash('sha256', random_bytes(12));
    }
}
