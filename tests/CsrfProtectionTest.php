<?php
declare(strict_types=1);

namespace Tests;

use
    Fyre\CSRF\CsrfProtection,
    PHPUnit\Framework\TestCase;

final class CsrfProtectionTest extends TestCase
{

    public function testEnable(): void
    {
        CsrfProtection::enable();

        $this->assertTrue(
            CsrfProtection::isEnabled()
        );
    }

    public function testDisable(): void
    {
        CsrfProtection::enable();
        CsrfProtection::disable();

        $this->assertFalse(
            CsrfProtection::isEnabled()
        );
    }

    public function testGetField(): void
    {
        $this->assertSame(
            'csrf_token',
            CsrfProtection::getField()
        );
    }

    public function testGetHeader(): void
    {
        $this->assertSame(
            'Csrf-Token',
            CsrfProtection::getHeader()
        );
    }

    public function testGetKey(): void
    {
        $this->assertSame(
            '_csrfToken',
            CsrfProtection::getKey()
        );
    }

    public function testGetToken(): void
    {
        $token = CsrfProtection::getToken();

        $this->assertMatchesRegularExpression(
            '/\w{12}/',
            $token
        );

        $this->assertSame(
            $token,
            CsrfProtection::getToken()
        );
    }

    public function testGetTokenHash(): void
    {
        $token = CsrfProtection::getToken();
        $tokenHash = CsrfProtection::getTokenHash();

        $this->assertTrue(
            password_verify($token, $tokenHash)
        );

        $this->assertNotSame(
            $tokenHash,
            CsrfProtection::getTokenHash()
        );
    }

    public function testSetField(): void
    {
        CsrfProtection::setField('token');

        $this->assertSame(
            'token',
            CsrfProtection::getField()
        );
    }

    public function testSetHeader(): void
    {
        CsrfProtection::setHeader('Security-Token');

        $this->assertSame(
            'Security-Token',
            CsrfProtection::getHeader()
        );
    }

    public function testSetKey(): void
    {
        CsrfProtection::setKey('_token');

        $this->assertSame(
            '_token',
            CsrfProtection::getKey()
        );
    }

    public function testSession(): void
    {
        $key = CsrfProtection::getKey();

        $this->assertSame(
            CsrfProtection::getToken(),
            $_SESSION[$key]
        );
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
