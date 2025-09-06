<?php
declare(strict_types=1);

namespace Tests;

use Fyre\Config\Config;
use Fyre\Container\Container;
use Fyre\Security\CsrfProtection;
use Fyre\Utility\Traits\MacroTrait;
use PHPUnit\Framework\TestCase;

use function class_uses;

final class CsrfProtectionTest extends TestCase
{
    protected CsrfProtection $csrfProtection;

    public function testGetCookieToken(): void
    {
        $this->assertSame(
            $this->csrfProtection->getCookieToken(),
            $this->csrfProtection->getCookieToken()
        );
    }

    public function testGetField(): void
    {
        $this->assertSame(
            'csrf_token',
            $this->csrfProtection->getField()
        );
    }

    public function testGetFormToken(): void
    {
        $this->assertNotSame(
            $this->csrfProtection->getFormToken(),
            $this->csrfProtection->getFormToken()
        );

        $this->assertNotSame(
            $this->csrfProtection->getCookieToken(),
            $this->csrfProtection->getFormToken()
        );
    }

    public function testGetHeader(): void
    {
        $this->assertSame(
            'Csrf-Token',
            $this->csrfProtection->getHeader()
        );
    }

    public function testMacroable(): void
    {
        $this->assertContains(
            MacroTrait::class,
            class_uses(CsrfProtection::class)
        );
    }

    protected function setUp(): void
    {
        $container = new Container();
        $container->singleton(Config::class);

        $container->use(Config::class)->set('Csrf.salt', 'l2wyQow3eTwQeTWcfZnlgU8FnbiWljpGjQvNP2pL');

        $this->csrfProtection = $container->build(CsrfProtection::class);
    }
}
