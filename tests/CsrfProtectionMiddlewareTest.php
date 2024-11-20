<?php
declare(strict_types=1);

namespace Tests;

use Fyre\Config\Config;
use Fyre\Container\Container;
use Fyre\Middleware\MiddlewareQueue;
use Fyre\Middleware\RequestHandler;
use Fyre\Security\CsrfProtection;
use Fyre\Security\Exceptions\CsrfException;
use Fyre\Security\Middleware\CsrfProtectionMiddleware;
use Fyre\Server\ClientResponse;
use Fyre\Server\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CsrfProtectionMiddlewareTest extends TestCase
{
    protected Container $container;

    public function testCookieInvalid(): void
    {
        $this->expectException(CsrfException::class);

        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'headers' => [
                    'Csrf-Token' => $csrfProtection->getFormToken(),
                ],
                'globals' => [
                    'cookie' => [
                        'CsrfToken' => $csrfProtection->getCookieToken().'1',
                    ],
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    public function testCookieMissing(): void
    {
        $this->expectException(CsrfException::class);

        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'headers' => [
                    'Csrf-Token' => $csrfProtection->getFormToken(),
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    public function testFormTokenHeader(): void
    {
        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'headers' => [
                    'Csrf-Token' => $csrfProtection->getFormToken(),
                ],
                'globals' => [
                    'cookie' => [
                        'CsrfToken' => $csrfProtection->getCookieToken(),
                    ],
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    public function testFormTokenInvalid(): void
    {
        $this->expectException(CsrfException::class);

        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'globals' => [
                    'cookie' => [
                        'CsrfToken' => $csrfProtection->getCookieToken().'1',
                    ],
                    'post' => [
                        'csrf_token' => $csrfProtection->getFormToken(),
                    ],
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    public function testFormTokenMissing(): void
    {
        $this->expectException(CsrfException::class);

        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'globals' => [
                    'cookie' => [
                        'CsrfToken' => $csrfProtection->getCookieToken().'1',
                    ],
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    public function testFormTokenPost(): void
    {
        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
                'globals' => [
                    'cookie' => [
                        'CsrfToken' => $csrfProtection->getCookieToken(),
                    ],
                    'post' => [
                        'csrf_token' => $csrfProtection->getFormToken(),
                    ],
                ],
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );

        $request = $this->container->use(ServerRequest::class);

        $this->assertNull(
            $request->getPost('csrf_token')
        );
    }

    public function testGet(): void
    {
        $csrfProtection = $this->container->use(CsrfProtection::class);
        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );

        $request = $this->container->use(ServerRequest::class);

        $this->assertSame(
            $csrfProtection,
            $request->getParam('csrf')
        );

        $this->assertSame(
            $csrfProtection->getCookieToken(),
            $response->getCookie('CsrfToken')->getValue()
        );
    }

    public function testSkipCheck(): void
    {
        $this->container->use(Config::class)->set('Csrf.skipCheck', function(ServerRequest $request): bool {
            $this->assertInstanceOf(
                ServerRequest::class,
                $request
            );

            return true;
        });

        $middleware = $this->container->build(CsrfProtectionMiddleware::class);

        $queue = new MiddlewareQueue();
        $queue->add($middleware);

        $handler = $this->container->build(RequestHandler::class, ['queue' => $queue]);
        $request = $this->container->build(ServerRequest::class, [
            'options' => [
                'method' => 'post',
            ],
        ]);

        $response = $handler->handle($request);

        $this->assertInstanceOf(
            ClientResponse::class,
            $response
        );
    }

    protected function setUp(): void
    {
        $this->container = new Container();
        $this->container->singleton(Config::class);
        $this->container->singleton(CsrfProtection::class);

        $this->container->use(Config::class)->set('Csrf.salt', 'l2wyQow3eTwQeTWcfZnlgU8FnbiWljpGjQvNP2pL');
    }
}
