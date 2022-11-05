<?php
declare(strict_types=1);

namespace Tests;

use
    Fyre\CSRF\CsrfProtection,
    Fyre\CSRF\Exceptions\CsrfException,
    Fyre\CSRF\Middleware\CsrfProtectionMiddleware,
    Fyre\Middleware\MiddlewareQueue,
    Fyre\Middleware\RequestHandler,
    Fyre\Server\ServerRequest,
    PHPUnit\Framework\TestCase;

final class CsrfProtectionMiddlewareTest extends TestCase
{

    public function testConfig(): void
    {
        $middleware = new CsrfProtectionMiddleware([
            'field' => 'token',
            'header' => 'Security-Token',
            'key' => '_token'
        ]);

        $this->assertSame(
            'token',
            CsrfProtection::getField()
        );

        $this->assertSame(
            'Security-Token',
            CsrfProtection::getHeader()
        );

        $this->assertSame(
            '_token',
            CsrfProtection::getKey()
        );
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testGet(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $response = $handler->handle($request);
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testExclude(): void
    {
        $middleware = new CsrfProtectionMiddleware([
            'exclude' => [
                '.*'
            ]
        ]);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $request->setMethod('post');

        $response = $handler->handle($request);
    }

    public function testTokenPost(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $request->setMethod('post');

        $field = CsrfProtection::getField();

        $request->setGlobals('post', [
            $field => CsrfProtection::getTokenHash()
        ]);

        $response = $handler->handle($request);

        $this->assertNull(
            $request->getPost($field)
        );
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testTokenHeader(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $request->setMethod('post');

        $header = CsrfProtection::getHeader();

        $request->setHeader($header, CsrfProtection::getTokenHash());

        $response = $handler->handle($request);
    }

    public function testTokenInvalid(): void
    {
        $this->expectException(CsrfException::class);

        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $request->setMethod('post');

        $response = $handler->handle($request);
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testTokenInvalidDisabled(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest;

        $request->setMethod('post');

        CsrfProtection::disable();

        $response = $handler->handle($request);
    }

    protected function setUp(): void
    {
        CsrfProtection::setField('csrf_token');
        CsrfProtection::setHeader('Csrf-Token');
        CsrfProtection::setKey('_csrfToken');
        CsrfProtection::setExcludedPaths([]);

        $_SESSION = [];
    }

}
