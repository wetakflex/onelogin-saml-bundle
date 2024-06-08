<?php
// SPDX-License-Identifier: BSD-3-Clause

declare(strict_types=1);

namespace Nbgrp\Tests\OneloginSamlBundle\Onelogin;

use Nbgrp\OneloginSamlBundle\Onelogin\AuthRegistry;
use Nbgrp\OneloginSamlBundle\Onelogin\AuthRegistryInterface;
use OneLogin\Saml2\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(AuthRegistry::class)]
final class AuthRegistryTest extends TestCase
{
    private AuthRegistryInterface $registry;

    public function testRegistry(): void
    {
        $defaultAuth = self::createStub(Auth::class);
        $this->registry->addService('default', $defaultAuth);

        $additionalAuth = self::createStub(Auth::class);
        $this->registry->addService('additional', $additionalAuth);

        self::assertTrue($this->registry->hasService('default'));
        self::assertTrue($this->registry->hasService('additional'));
        self::assertFalse($this->registry->hasService('undefined'));

        self::assertSame($this->registry->getService('additional'), $additionalAuth);
        self::assertSame($this->registry->getDefaultService(), $defaultAuth);
    }

    public function testGetNotExistsServiceException(): void
    {
        $this->expectException(\OutOfBoundsException::class);
        $this->expectExceptionMessage('Auth service for key "undefined" does not exists.');
        $this->registry->getService('undefined');
    }

    public function testAddExistenceServiceException(): void
    {
        $defaultAuth = self::createStub(Auth::class);
        $this->registry->addService('default', $defaultAuth);

        $this->expectException(\OverflowException::class);
        $this->expectExceptionMessage('Auth service with key "default" already exists.');
        $this->registry->addService('default', $defaultAuth);
    }

    public function testEmptyRegistryDefaultService(): void
    {
        $this->expectException(\UnderflowException::class);
        $this->expectExceptionMessage('There is no configured Auth services.');

        $this->registry->getDefaultService();
    }

    protected function setUp(): void
    {
        $this->registry = new AuthRegistry();
    }
}
