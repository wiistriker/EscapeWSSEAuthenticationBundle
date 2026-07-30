<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Factory;

use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class WSSEFactoryTest extends TestCase
{
    private const DATE_FORMAT = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

    public function testGetPosition()
    {
        $this->assertSame('pre_auth', (new WSSEFactory())->getPosition());
    }

    public function testGetKey()
    {
        $this->assertSame('wsse', (new WSSEFactory())->getKey());
    }

    public function testGetPriority()
    {
        $this->assertSame(0, (new WSSEFactory())->getPriority());
    }

    public function testIsRememberMeAware()
    {
        $factory = new WSSEFactory();

        $method = new \ReflectionMethod($factory, 'isRememberMeAware');
        $method->setAccessible(true);

        $this->assertFalse($method->invoke($factory, []));
    }

    public function testAddConfigurationDefaults()
    {
        $config = $this->processConfiguration(['realm' => 'somerealm']);

        $this->assertSame('somerealm', $config['realm']);
        $this->assertSame('_password', $config['profile']);
        $this->assertSame(300, $config['lifetime']);
        $this->assertSame(61, $config['future_allowed_seconds']);
        $this->assertSame(self::DATE_FORMAT, $config['date_format']);
        $this->assertNull($config['nonce_cache_service']);
        $this->assertTrue($config['remember_me']);
        $this->assertArrayNotHasKey('encoder', $config);

        // addConfiguration() re-declares "failure_handler", which AbstractFactory
        // had already registered with a null default; the later declaration wins
        // and drops that default, so the key disappears when unset.
        $this->assertArrayNotHasKey('failure_handler', $config);
    }

    public function testAddConfigurationAcceptsEncoderAndFailureHandler()
    {
        $config = $this->processConfiguration([
            'realm' => 'somerealm',
            'encoder' => [
                'algorithm' => 'sha256',
                'encodeHashAsBase64' => false,
                'iterations' => 2,
            ],
            'failure_handler' => 'app.wsse.failure_handler',
            'nonce_cache_service' => 'cache.app',
        ]);

        $this->assertSame(
            ['algorithm' => 'sha256', 'encodeHashAsBase64' => false, 'iterations' => 2],
            $config['encoder']
        );
        $this->assertSame('app.wsse.failure_handler', $config['failure_handler']);
        $this->assertSame('cache.app', $config['nonce_cache_service']);
    }

    public function testCreateAuthenticator()
    {
        $container = new ContainerBuilder();

        $encoder = [
            'algorithm' => 'sha1',
            'encodeHashAsBase64' => true,
            'iterations' => 1,
        ];

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'foo-firewall',
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'encoder' => $encoder,
                'lifetime' => 300,
                'date_format' => self::DATE_FORMAT,
                'nonce_cache_service' => 'cache.app',
            ],
            'some.user_provider'
        );

        $this->assertSame('security.authenticator.wsse.foo-firewall', $authenticatorId);
        $this->assertTrue($container->hasDefinition($authenticatorId));

        $definition = $container->getDefinition($authenticatorId);

        $this->assertEquals(new Reference('some.user_provider'), $definition->getArgument('$userProvider'));
        $this->assertEquals(new Reference('escape_wsse_authentication.encoder.foo-firewall'), $definition->getArgument('$passwordHasher'));
        $this->assertEquals(new Reference('cache.app'), $definition->getArgument('$nonceCache'));
        $this->assertSame(
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'lifetime' => 300,
                'date_format' => self::DATE_FORMAT,
                'nonce_cache_service' => 'cache.app',
            ],
            $definition->getArgument('$options')
        );

        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.encoder.foo-firewall'));
        $this->assertSame(
            [
                'index_0' => 'sha1',
                'index_1' => true,
                'index_2' => 1,
            ],
            $container->getDefinition('escape_wsse_authentication.encoder.foo-firewall')->getArguments()
        );
    }

    /**
     * Without an "encoder" key the hasher definition must inherit every argument
     * from its parent, and without "nonce_cache_service" the cache reference set
     * by the bundle extension must be left untouched.
     */
    public function testCreateAuthenticatorWithoutOptionalConfiguration()
    {
        $container = new ContainerBuilder();

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'bar-firewall',
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'lifetime' => 300,
                'date_format' => self::DATE_FORMAT,
                'future_allowed_seconds' => 61,
                'nonce_cache_service' => null,
                'failure_handler' => null,
            ],
            'some.user_provider'
        );

        $definition = $container->getDefinition($authenticatorId);

        $this->assertArrayNotHasKey('$nonceCache', $definition->getArguments());
        $this->assertSame([], $container->getDefinition('escape_wsse_authentication.encoder.bar-firewall')->getArguments());
    }

    /**
     * NOTE: this asserts current behaviour - a failure handler is wired in even
     * when the firewall does not configure one, which makes the null branch in
     * WSSEAuthenticator::onAuthenticationFailure() unreachable.
     */
    public function testCreateAuthenticatorAlwaysWiresAFailureHandler()
    {
        $container = new ContainerBuilder();

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'baz-firewall',
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'lifetime' => 300,
                'date_format' => self::DATE_FORMAT,
                'nonce_cache_service' => null,
            ],
            'some.user_provider'
        );

        $failureHandlerId = 'security.authentication.failure_handler.baz-firewall.wsse';

        $this->assertTrue($container->hasDefinition($failureHandlerId));
        $this->assertEquals(
            new Reference($failureHandlerId),
            $container->getDefinition($authenticatorId)->getArgument('$failureHandler')
        );
    }

    /**
     * @dataProvider provideUnsupportedLegacyMethods
     */
    public function testLegacyAuthenticationSystemIsNotSupported(string $method, int $arguments)
    {
        $factory = new WSSEFactory();

        $reflection = new \ReflectionMethod($factory, $method);
        $reflection->setAccessible(true);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('The old authentication system is not supported with wsse.');

        $reflection->invokeArgs($factory, array_slice(
            [new ContainerBuilder(), 'foo-firewall', [], 'some.user_provider'],
            0,
            $arguments
        ));
    }

    public function provideUnsupportedLegacyMethods(): array
    {
        return [
            'createAuthProvider' => ['createAuthProvider', 4],
            'getListenerId' => ['getListenerId', 0],
            'createListener' => ['createListener', 4],
            'createEntryPoint' => ['createEntryPoint', 4],
        ];
    }

    private function processConfiguration(array $config): array
    {
        $treeBuilder = new TreeBuilder('wsse');

        (new WSSEFactory())->addConfiguration($treeBuilder->getRootNode());

        $tree = $treeBuilder->buildTree();

        return $tree->finalize($tree->normalize($config));
    }
}
