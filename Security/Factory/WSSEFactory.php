<?php

namespace Escape\WSSEAuthenticationBundle\Security\Factory;

use Escape\WSSEAuthenticationBundle\Security\Http\Authenticator\WSSEAuthenticator;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class WSSEFactory extends AbstractFactory implements AuthenticatorFactoryInterface
{
    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->scalarNode('provider')->end()
                ->scalarNode('realm')->defaultValue(null)->end()
                ->scalarNode('profile')->defaultValue('UsernameToken')->end()
                ->scalarNode('lifetime')->defaultValue(300)->end()
                ->scalarNode('date_format')->defaultValue(
                    '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
                )->end()
                ->arrayNode('encoder')
                    ->children()
                        ->scalarNode('algorithm')->end()
                        ->scalarNode('encodeHashAsBase64')->end()
                        ->scalarNode('iterations')->end()
                    ->end()
                ->end()
                ->scalarNode('nonce_cache_service_id')->defaultValue(null)->end()
            ->end();
    }

    public function getKey(): string
    {
        return 'wsse';
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $authenticatorId = 'security.authenticator.wsse.'.$firewallName;

        $container
            ->register($authenticatorId, WSSEAuthenticator::class)
            ->addArgument(new Reference($userProviderId))
            ->addArgument(new Reference('escape_wsse_authentication.encoder'))
            ->addArgument($config)
        ;

        return $authenticatorId;
    }

    public function getPriority(): int
    {
        return 0;
    }

    public function getPosition(): string
    {
        return 'pre_auth';
    }

    protected function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        throw new \Exception('The old authentication system is not supported with wsse.');
    }

    protected function getListenerId(): string
    {
        throw new \Exception('The old authentication system is not supported with wsse.');
    }

    protected function createListener(ContainerBuilder $container, string $id, array $config, string $userProvider)
    {
        throw new \Exception('The old authentication system is not supported with wsse.');
    }

    protected function createEntryPoint(ContainerBuilder $container, string $id, array $config, ?string $defaultEntryPointId): ?string
    {
        throw new \Exception('The old authentication system is not supported with wsse.');
    }
}
