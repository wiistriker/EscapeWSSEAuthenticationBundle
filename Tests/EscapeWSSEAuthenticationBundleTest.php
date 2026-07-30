<?php

namespace Escape\WSSEAuthenticationBundle\Tests;

use Escape\WSSEAuthenticationBundle\EscapeWSSEAuthenticationBundle;
use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class EscapeWSSEAuthenticationBundleTest extends TestCase
{
    public function testBuildRegistersTheAuthenticatorFactory()
    {
        $securityExtension = $this->createMock(SecurityExtension::class);
        $securityExtension->method('getAlias')->willReturn('security');
        $securityExtension->expects($this->once())
            ->method('addAuthenticatorFactory')
            ->with($this->isInstanceOf(WSSEFactory::class));

        $container = new ContainerBuilder();
        $container->registerExtension($securityExtension);

        (new EscapeWSSEAuthenticationBundle())->build($container);
    }
}
