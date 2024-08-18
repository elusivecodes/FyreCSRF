<?php
declare(strict_types=1);

namespace Fyre\Security\Middleware;

use Fyre\Middleware\Middleware;
use Fyre\Middleware\RequestHandler;
use Fyre\Security\CsrfProtection;
use Fyre\Server\ClientResponse;
use Fyre\Server\ServerRequest;

use function array_replace;

/**
 * CsrfProtectionMiddleware
 */
class CsrfProtectionMiddleware extends Middleware
{
    protected static array $defaults = [
        'field' => 'csrf_token',
        'header' => 'Csrf-Token',
        'key' => '_csrfToken',
        'skipCheck' => null,
    ];

    /**
     * New CsrfProtectionMiddleware constructor.
     *
     * @param array $options Options for the middleware.
     */
    public function __construct(array $options = [])
    {
        $options = array_replace(static::$defaults, $options);

        CsrfProtection::enable();
        CsrfProtection::setField($options['field']);
        CsrfProtection::setHeader($options['header']);
        CsrfProtection::setKey($options['key']);
        CsrfProtection::skipCheckCallback($options['skipCheck']);
    }

    /**
     * Process a ServerRequest.
     *
     * @param ServerRequest $request The ServerRequest.
     * @param RequestHandler $handler The RequestHandler.
     * @return ClientResponse The ClientResponse.
     */
    public function process(ServerRequest $request, RequestHandler $handler): ClientResponse
    {
        if (CsrfProtection::isEnabled()) {
            CsrfProtection::checkToken($request);
        }

        return $handler->handle($request);
    }
}
