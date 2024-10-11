<?php
declare(strict_types=1);

namespace Tests;

use Fyre\Middleware\MiddlewareQueue;
use Fyre\Middleware\RequestHandler;
use Fyre\Security\CsrfProtection;
use Fyre\Security\Exceptions\CsrfException;
use Fyre\Security\Middleware\CsrfProtectionMiddleware;
use Fyre\Server\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CsrfProtectionMiddlewareTest extends TestCase
{
    public function testConfig(): void
    {
        $middleware = new CsrfProtectionMiddleware([
            'field' => 'token',
            'header' => 'Security-Token',
            'key' => '_token',
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
        $request = new ServerRequest();

        $response = $handler->handle($request);
    }

    public function testSkipCheck(): void
    {
        $middleware = new CsrfProtectionMiddleware([
            'skipCheck' => function(ServerRequest $request): bool {
                $this->assertInstanceOf(
                    ServerRequest::class,
                    $request
                );

                return true;
            },
        ]);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest([
            'method' => 'post',
        ]);

        $response = $handler->handle($request);
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testTokenHeader(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $header = CsrfProtection::getHeader();

        $handler = new RequestHandler($queue);
        $request = new ServerRequest([
            'method' => 'post',
            'headers' => [
                $header => CsrfProtection::getTokenHash(),
            ],
        ]);

        $response = $handler->handle($request);
    }

    public function testTokenInvalid(): void
    {
        $this->expectException(CsrfException::class);

        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = new RequestHandler($queue);
        $request = new ServerRequest([
            'method' => 'post',
        ]);

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
        $request = new ServerRequest([
            'method' => 'post',
        ]);

        CsrfProtection::disable();

        $response = $handler->handle($request);
    }

    public function testTokenPost(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $field = CsrfProtection::getField();

        $request = new ServerRequest([
            'method' => 'post',
            'globals' => [
                'post' => [
                    $field => CsrfProtection::getTokenHash(),
                ],
            ],
        ]);
        $handler = new RequestHandler($queue, beforeHandle: function(ServerRequest $newRequest) use (&$request): void {
            $request = $newRequest;
        });

        $response = $handler->handle($request);

        $this->assertNull(
            $request->getPost($field)
        );
    }

    protected function setUp(): void
    {
        CsrfProtection::setField('csrf_token');
        CsrfProtection::setHeader('Csrf-Token');
        CsrfProtection::setKey('_csrfToken');
        CsrfProtection::skipCheckCallback(null);

        $_SESSION = [];
    }
}
