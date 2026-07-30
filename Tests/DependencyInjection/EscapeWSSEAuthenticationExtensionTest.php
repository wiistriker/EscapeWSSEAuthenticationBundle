<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection;

use Escape\WSSEAuthenticationBundle\DependencyInjection\EscapeWSSEAuthenticationExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;

class EscapeWSSEAuthenticationExtensionTest extends TestCase
{
    public function testGetAlias()
    {
        $this->assertSame('escape_wsse_authentication', (new EscapeWSSEAuthenticationExtension())->getAlias());
    }

    public function testLoadWithDefaultConfiguration()
    {
        $container = new ContainerBuilder();

        (new EscapeWSSEAuthenticationExtension())->load([[]], $container);

        $this->assertSame(
            MessageDigestPasswordHasher::class,
            $container->getParameter('escape_wsse_authentication.encoder.class')
        );

        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.encoder'));
        $this->assertSame(
            ['sha1', true, 1],
            $container->getDefinition('escape_wsse_authentication.encoder')->getArguments()
        );

        $authenticator = $container->getDefinition('escape_wsse_authentication.authenticator');

        $this->assertTrue($authenticator->isAbstract());
        $this->assertEquals(new Reference('cache.app'), $authenticator->getArgument('$nonceCache'));
        $this->assertSame([], $authenticator->getArgument('$options'));
    }

    public function testLoadWithCustomConfiguration()
    {
        $container = new ContainerBuilder();

        (new EscapeWSSEAuthenticationExtension())->load([
            [
                'authentication_encoder_class' => 'App\Security\CustomHasher',
                'nonce_cache_service' => 'app.wsse_nonce_cache',
            ],
        ], $container);

        $this->assertSame(
            'App\Security\CustomHasher',
            $container->getParameter('escape_wsse_authentication.encoder.class')
        );
        $this->assertEquals(
            new Reference('app.wsse_nonce_cache'),
            $container->getDefinition('escape_wsse_authentication.authenticator')->getArgument('$nonceCache')
        );
    }
}
