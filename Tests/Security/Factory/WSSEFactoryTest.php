<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Factory;

use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class WSSEFactoryTest extends TestCase
{
    public function testGetPosition()
    {
        $factory = new WSSEFactory();
        $this->assertEquals('pre_auth', $factory->getPosition());
    }

    public function testGetKey()
    {
        $factory = new WSSEFactory();
        $this->assertEquals('wsse', $factory->getKey());
    }

    public function testGetPriority()
    {
        $factory = new WSSEFactory();
        $this->assertEquals(0, $factory->getPriority());
    }

    protected function getFactory()
    {
        return $this->getMockForAbstractClass(WSSEFactory::class, []);
    }

    public function testCreateAuthenticator()
    {
        $factory = new WSSEFactory();

        $container = new ContainerBuilder();

        $realm = 'somerealm';
        $profile = 'someprofile';
        $lifetime = 300;
        $date_format = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

        $algorithm = 'sha1';
        $encodeHashAsBase64 = true;
        $iterations = 1;

        $encoder = array(
            'algorithm' => $algorithm,
            'encodeHashAsBase64' => $encodeHashAsBase64,
            'iterations' => $iterations
        );

        $authenticator_id = $factory->createAuthenticator(
            $container,
            'foo-firewall',
            [
                'realm' => $realm,
                'profile' => $profile,
                'encoder' => $encoder,
                'lifetime' => $lifetime,
                'date_format' => $date_format,
                'nonce_cache_service_id' => 'cache.app'
            ],
            'test'
        );

        $this->assertTrue($container->hasDefinition('security.authenticator.wsse.foo-firewall'));
        $definition = $container->getDefinition('security.authenticator.wsse.foo-firewall');
        $this->assertEquals(
            [
                'date_format' => $date_format,
                'lifetime' => 300,
                'realm' => 'somerealm',
                'profile' => 'someprofile'
            ],
            $definition->getArgument(4)
        );

        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.encoder.foo-firewall'));
        $definition = $container->getDefinition('escape_wsse_authentication.encoder.foo-firewall');
        $this->assertEquals(
            [
                'index_0' => $algorithm,
                'index_1' => $encodeHashAsBase64,
                'index_2' => $iterations
            ],
            $definition->getArguments()
        );
    }

    public function Create()
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('escape_wsse_authentication.provider');

        $realm = 'somerealm';
        $profile = 'someprofile';
        $lifetime = 300;
        $date_format = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

        $algorithm = 'sha1';
        $encodeHashAsBase64 = true;
        $iterations = 1;

        $encoder = array(
            'algorithm' => $algorithm,
            'encodeHashAsBase64' => $encodeHashAsBase64,
            'iterations' => $iterations
        );

        list($authProviderId,
            $listenerId,
            $entryPointId
            ) = $factory->create(
            $container,
            'foo',
            array(
                'realm' => $realm,
                'profile' => $profile,
                'encoder' => $encoder,
                'lifetime' => $lifetime,
                'date_format' => $date_format
            ),
            'user_provider',
            'entry_point'
        );

        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.encoder.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.encoder.foo');
        $this->assertEquals(
            array(
                'index_0' => $algorithm,
                'index_1' => $encodeHashAsBase64,
                'index_2' => $iterations
            ),
            $definition->getArguments()
        );

        //nonce cache
        $nonceCacheId = $factory->getNonceCacheId();

        $this->assertEquals('escape_wsse_authentication.nonce_cache.foo', $nonceCacheId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.nonce_cache.foo'));

        //auth provider
        $this->assertEquals('escape_wsse_authentication.provider.foo', $authProviderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.provider.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.provider.foo');
        $this->assertEquals(
            array(
                'index_1' => new Reference('user_provider'),
                'index_2' => 'foo',
                'index_3' => new Reference($encoderId),
                'index_4' => new Reference($nonceCacheId),
                'index_5' => $lifetime,
                'index_6' => $date_format
            ),
            $definition->getArguments()
        );

        //listener
        $this->assertEquals('escape_wsse_authentication.listener.foo', $listenerId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.listener.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.listener.foo');
        $this->assertEquals(
            array(
                0 => 'foo',
                1 => new Reference($entryPointId)
            ),
            $definition->getArguments()
        );

        //entry point
        $this->assertEquals('escape_wsse_authentication.entry_point.foo', $entryPointId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.entry_point.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.entry_point.foo');
        $this->assertEquals(
            array(
                'index_1' => $realm,
                'index_2' => $profile
            ),
            $definition->getArguments()
        );
    }
}
