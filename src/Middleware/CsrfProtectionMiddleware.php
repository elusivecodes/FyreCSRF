<?php
declare(strict_types=1);

namespace Fyre\CSRF\Middleware;

use
    Fyre\Middleware\Middleware,
    Fyre\Middleware\RequestHandler,
    Fyre\CSRF\CsrfProtection,
    Fyre\Server\ClientResponse,
    Fyre\Server\ServerRequest;

use function
    array_replace_recursive;

/**
 * CsrfProtectionMiddleware
 */
class CsrfProtectionMiddleware extends Middleware
{

    protected static array $defaults = [
        'field' => 'csrf_token',
        'header' => 'Csrf-Token',
        'key' => '_csrfToken',
        'exclude' => []
    ];

    /**
     * New CsrfProtectionMiddleware constructor.
     * @param array $options Options for the middleware.
     */
    public function __construct(array $options = [])
    {
        $options = array_replace_recursive(static::$defaults, $options);

        CsrfProtection::setField($options['field']);
        CsrfProtection::setHeader($options['header']);
        CsrfProtection::setKey($options['key']);
        CsrfProtection::setExcludedPaths($options['exclude']);
    }

    /**
     * Process a ServerRequest.
     * @param ServerRequest $request The ServerRequest.
     * @param RequestHandler $handler The RequestHandler.
     * @return ClientResponse The ClientResponse.
     */
    public function process(ServerRequest $request, RequestHandler $handler): ClientResponse
    {
        CsrfProtection::checkToken($request);

        return $handler->handle($request);
    }

}
