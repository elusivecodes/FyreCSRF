<?php
declare(strict_types=1);

namespace Fyre\Security\Middleware;

use Closure;
use Fyre\Middleware\Middleware;
use Fyre\Security\CsrfProtection;
use Fyre\Server\ClientResponse;
use Fyre\Server\ServerRequest;

/**
 * CsrfProtectionMiddleware
 */
class CsrfProtectionMiddleware extends Middleware
{
    protected CsrfProtection $csrfProtection;

    /**
     * New CsrfProtectionMiddleware constructor.
     *
     * @param CsrfProtection $csrfProtection The CsrfProtection.
     */
    public function __construct(CsrfProtection $csrfProtection)
    {
        $this->csrfProtection = $csrfProtection;
    }

    /**
     * Handle a ServerRequest.
     *
     * @param ServerRequest $request The ServerRequest.
     * @param Closure $next The RequestHandler.
     * @return ClientResponse The ClientResponse.
     */
    public function handle(ServerRequest $request, Closure $next): ClientResponse
    {
        $request = $this->csrfProtection->checkToken($request);

        return $this->csrfProtection->beforeResponse($request, $next($request));
    }
}
