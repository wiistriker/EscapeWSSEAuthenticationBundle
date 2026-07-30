<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Factory;

use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class WSSEFactoryTest extends TestCase
{
    public function testGetKey()
    {
        $this->assertSame('wsse', (new WSSEFactory())->getKey());
    }

    public function testGetPriority()
    {
        $this->assertSame(0, (new WSSEFactory())->getPriority());
    }

    public function testAddConfigurationDefaults()
    {
        $config = $this->processConfiguration(['realm' => 'somerealm']);

        $this->assertSame('somerealm', $config['realm']);
        $this->assertSame('_password', $config['profile']);
        $this->assertSame(300, $config['lifetime']);
        $this->assertSame(61, $config['future_allowed_seconds']);
        $this->assertSame(WSSEFactory::DEFAULT_DATE_FORMAT, $config['date_format']);
        $this->assertNull($config['nonce_cache_service']);
        $this->assertNull($config['failure_handler']);
        $this->assertArrayNotHasKey('encoder', $config);
        $this->assertArrayNotHasKey('provider', $config);
    }

    public function testAddConfigurationAcceptsEncoderProviderAndFailureHandler()
    {
        $config = $this->processConfiguration([
            'realm' => 'somerealm',
            'provider' => 'wsse_users',
            'encoder' => [
                'algorithm' => 'sha256',
                'encodeHashAsBase64' => false,
                'iterations' => 2,
            ],
            'failure_handler' => 'app.wsse.failure_handler',
            'nonce_cache_service' => 'app.wsse_nonce_cache',
        ]);

        $this->assertSame('wsse_users', $config['provider']);
        $this->assertSame(
            ['algorithm' => 'sha256', 'encodeHashAsBase64' => false, 'iterations' => 2],
            $config['encoder']
        );
        $this->assertSame('app.wsse.failure_handler', $config['failure_handler']);
        $this->assertSame('app.wsse_nonce_cache', $config['nonce_cache_service']);
    }

    public function testCreateAuthenticator()
    {
        $container = new ContainerBuilder();

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'foo-firewall',
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'lifetime' => 300,
                'date_format' => WSSEFactory::DEFAULT_DATE_FORMAT,
                'future_allowed_seconds' => 61,
                'nonce_cache_service' => 'app.wsse_nonce_cache',
                'failure_handler' => null,
                'encoder' => [
                    'algorithm' => 'sha1',
                    'encodeHashAsBase64' => true,
                    'iterations' => 1,
                ],
            ],
            'some.user_provider'
        );

        $this->assertSame('security.authenticator.wsse.foo-firewall', $authenticatorId);
        $this->assertTrue($container->hasDefinition($authenticatorId));

        $definition = $container->getDefinition($authenticatorId);

        $this->assertEquals(new Reference('some.user_provider'), $definition->getArgument('$userProvider'));
        $this->assertEquals(new Reference('escape_wsse_authentication.encoder.foo-firewall'), $definition->getArgument('$passwordHasher'));
        $this->assertEquals(new Reference('app.wsse_nonce_cache'), $definition->getArgument('$nonceCache'));

        // container-level configuration must not leak into the authenticator options
        $this->assertSame(
            [
                'realm' => 'somerealm',
                'profile' => 'someprofile',
                'lifetime' => 300,
                'date_format' => WSSEFactory::DEFAULT_DATE_FORMAT,
                'future_allowed_seconds' => 61,
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
            $this->minimalFirewallConfig(),
            'some.user_provider'
        );

        $definition = $container->getDefinition($authenticatorId);

        $this->assertArrayNotHasKey('$nonceCache', $definition->getArguments());
        $this->assertSame([], $container->getDefinition('escape_wsse_authentication.encoder.bar-firewall')->getArguments());
    }

    /**
     * A firewall that configures no failure handler must not get one: Symfony's
     * default handler redirects and touches the session, which cannot work on the
     * stateless firewalls WSSE targets, and it would swallow the 401 challenge.
     */
    public function testCreateAuthenticatorWiresNoFailureHandlerByDefault()
    {
        $container = new ContainerBuilder();

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'baz-firewall',
            $this->minimalFirewallConfig(),
            'some.user_provider'
        );

        $this->assertNull($container->getDefinition($authenticatorId)->getArgument('$failureHandler'));
    }

    public function testCreateAuthenticatorWiresAConfiguredFailureHandler()
    {
        $container = new ContainerBuilder();

        $authenticatorId = (new WSSEFactory())->createAuthenticator(
            $container,
            'qux-firewall',
            $this->minimalFirewallConfig(['failure_handler' => 'app.wsse.failure_handler']),
            'some.user_provider'
        );

        $this->assertEquals(
            new Reference('app.wsse.failure_handler'),
            $container->getDefinition($authenticatorId)->getArgument('$failureHandler')
        );
    }

    private function minimalFirewallConfig(array $overrides = []): array
    {
        return array_merge([
            'realm' => 'somerealm',
            'profile' => 'someprofile',
            'lifetime' => 300,
            'date_format' => WSSEFactory::DEFAULT_DATE_FORMAT,
            'future_allowed_seconds' => 61,
            'nonce_cache_service' => null,
            'failure_handler' => null,
        ], $overrides);
    }

    private function processConfiguration(array $config): array
    {
        $treeBuilder = new TreeBuilder('wsse');

        (new WSSEFactory())->addConfiguration($treeBuilder->getRootNode());

        $tree = $treeBuilder->buildTree();

        return $tree->finalize($tree->normalize($config));
    }
}
