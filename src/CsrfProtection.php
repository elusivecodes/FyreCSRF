<?php
declare(strict_types=1);

namespace Fyre\Security;

use Closure;
use Fyre\Config\Config;
use Fyre\Container\Container;
use Fyre\Security\Exceptions\CsrfException;
use Fyre\Server\ClientResponse;
use Fyre\Server\ServerRequest;
use Fyre\Utility\Traits\MacroTrait;

use function array_key_exists;
use function array_replace_recursive;
use function base64_decode;
use function base64_encode;
use function chr;
use function hash_equals;
use function hash_hmac;
use function in_array;
use function ord;
use function random_bytes;
use function strlen;
use function substr;
use function time;

/**
 * CsrfProtection
 */
class CsrfProtection
{
    use MacroTrait;

    protected const CHECK_METHODS = [
        'delete',
        'patch',
        'post',
        'put',
    ];

    protected const TOKEN_LENGTH = 16;

    protected static array $defaults = [
        'cookie' => [
            'name' => 'CsrfToken',
            'expires' => 0,
            'domain' => '',
            'path' => '/',
            'secure' => true,
            'httpOnly' => false,
            'sameSite' => 'Lax',
        ],
        'field' => 'csrf_token',
        'header' => 'Csrf-Token',
        'salt' => null,
        'skipCheck' => null,
    ];

    protected array $cookieOptions;

    protected string|null $field;

    protected string|null $header;

    protected string $salt;

    protected Closure|null $skipCheck;

    protected string|null $token;

    /**
     * New CsrfProtection constructor.
     *
     * @param Container $container The Container.
     * @param Config $config The Config.
     */
    public function __construct(
        protected Container $container,
        Config $config
    ) {
        $options = array_replace_recursive(static::$defaults, $config->get('Csrf', []));

        $this->cookieOptions = $options['cookie'];
        $this->field = $options['field'];
        $this->header = $options['header'];
        $this->salt = $options['salt'];
        $this->skipCheck = $options['skipCheck'];
    }

    /**
     * Update the ClientResponse before sending to client.
     *
     * @param ServerRequest $request The ServerRequest.
     * @param ClientResponse $response The ClientResponse.
     * @return ClientResponse The ClientResponse.
     */
    public function beforeResponse(ServerRequest $request, ClientResponse $response): ClientResponse
    {
        if ($request->getCookie($this->cookieOptions['name'])) {
            return $response;
        }

        return $response->setCookie($this->cookieOptions['name'], $this->getCookieToken(), [
            'expires' => $this->cookieOptions['expires'] ?
                time() + $this->cookieOptions['expires'] :
                null,
            'domain' => $this->cookieOptions['domain'],
            'path' => $this->cookieOptions['path'],
            'secure' => $this->cookieOptions['secure'],
            'httpOnly' => $this->cookieOptions['httpOnly'],
            'sameSite' => $this->cookieOptions['sameSite'],
        ]);
    }

    /**
     * Check CSRF token.
     *
     * @param ServerRequest $request The ServerRequest.
     * @return ServerRequest The ServerRequest.
     *
     * @throws CsrfException if the token is invalid.
     */
    public function checkToken(ServerRequest $request): ServerRequest
    {
        if ($request->getParam('csrf')) {
            throw CsrfException::forCsrfAlreadySet();
        }

        $request = $request->setParam('csrf', $this);

        $hasData = in_array($request->getMethod(), static::CHECK_METHODS);
        $userToken = null;

        if ($hasData && $this->field) {
            $data = $request->getPost();

            if (array_key_exists($this->field, $data)) {
                $userToken = $data[$this->field];

                unset($data[$this->field]);

                $request = $request->setGlobal('post', $data);
            }
        }

        $this->token = $request->getCookie($this->cookieOptions['name']);

        if (!$hasData || ($this->skipCheck && $this->container->call($this->skipCheck, ['request' => $request]) === true)) {
            return $request;
        }

        $userToken ??= $request->getHeaderValue($this->header);

        if (
            !$userToken ||
            !$this->token ||
            !$this->verifyToken($this->token) ||
            !hash_equals($this->unsaltToken($userToken), $this->token)
        ) {
            throw CsrfException::forInvalidToken();
        }

        return $request;
    }

    /**
     * Get the CSRF cookie token.
     *
     * @return string The CSRF user token.
     */
    public function getCookieToken(): string
    {
        return $this->token ??= $this->createToken();
    }

    /**
     * Get the CSRF token field name.
     *
     * @return string The CSRF token field name.
     */
    public function getField(): string
    {
        return $this->field;
    }

    /**
     * Get the CSRF form token.
     *
     * @return string The CSRF form token.
     */
    public function getFormToken(): string
    {
        return $this->saltToken($this->getCookieToken());
    }

    /**
     * Get the CSRF token header name.
     *
     * @return string The CSRF token header name.
     */
    public function getHeader(): string
    {
        return $this->header;
    }

    /**
     * Create a token.
     *
     * @return string The token.
     */
    protected function createToken(): string
    {
        $token = random_bytes(static::TOKEN_LENGTH);
        $token .= hash_hmac('sha1', $token, $this->salt);

        return base64_encode($token);
    }

    /**
     * Add salt to a token.
     *
     * @param string $token The unsalted token
     * @return string The salted token.
     */
    protected function saltToken(string $token): string|null
    {
        $decoded = base64_decode($token, true);

        if ($decoded === false) {
            return null;
        }

        $length = strlen($decoded);
        $salt = random_bytes($length);
        $salted = '';
        for ($i = 0; $i < $length; $i++) {
            // XOR the token and salt together so that we can reverse it later.
            $salted .= chr(ord($decoded[$i]) ^ ord($salt[$i]));
        }

        return base64_encode($salted.$salt);
    }

    /**
     * Remove salt from a token.
     *
     * @param string $token The salted token
     * @return string The unsalted token.
     */
    protected function unsaltToken(string $token): string|null
    {
        $decoded = base64_decode($token, true);

        if ($decoded === false) {
            return null;
        }

        $length = static::TOKEN_LENGTH + 40;
        $salted = substr($decoded, 0, $length);
        $salt = substr($decoded, $length);

        $unsalted = '';
        for ($i = 0; $i < $length; $i++) {
            // Reverse the XOR to desalt.
            $unsalted .= chr(ord($salted[$i]) ^ ord($salt[$i]));
        }

        return base64_encode($unsalted);
    }

    /**
     * Verify a token is valid.
     *
     * @param string $token The token.
     * @return bool TRUE if the token is valid, otherwise FALSE.
     */
    protected function verifyToken(string $token): bool
    {
        $decoded = base64_decode($token, true);

        if ($decoded === false) {
            return false;
        }

        $length = strlen($decoded);

        if ($length <= static::TOKEN_LENGTH) {
            return false;
        }

        $key = substr($decoded, 0, static::TOKEN_LENGTH);
        $hmac = substr($decoded, static::TOKEN_LENGTH);

        $expectedHmac = hash_hmac('sha1', $key, $this->salt);

        return hash_equals($hmac, $expectedHmac);
    }
}
