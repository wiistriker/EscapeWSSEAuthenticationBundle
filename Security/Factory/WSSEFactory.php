<?php

namespace Escape\WSSEAuthenticationBundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\ChildDefinition;

class WSSEFactory extends AbstractFactory implements AuthenticatorFactoryInterface
{
    public const PRIORITY = 0;

    public function __construct()
    {
        $this->options = [];

        $this->addOption('realm');
        $this->addOption('profile', '_password');
        $this->addOption('lifetime', 300);
        $this->addOption('date_format', '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/');
        $this->addOption('future_allowed_seconds', 61);
        $this->addOption('nonce_cache_service');
        $this->addOption('failure_handler');

        $this->defaultFailureHandlerOptions = [];
        $this->defaultSuccessHandlerOptions = [];
    }

    public function getKey(): string
    {
        return 'wsse';
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getPosition(): string
    {
        return 'pre_auth';
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        parent::addConfiguration($builder);

        $builder
            ->children()
                ->arrayNode('encoder')
                    ->children()
                        ->scalarNode('algorithm')->end()
                        ->scalarNode('encodeHashAsBase64')->end()
                        ->scalarNode('iterations')->end()
                    ->end()
                ->end()
                ->scalarNode('failure_handler')->end()
            ->end()
        ;
    }

    protected function isRememberMeAware(array $config): bool
    {
        return false;
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $authenticatorId = 'security.authenticator.wsse.'.$firewallName;

        $passwordHasherId = 'escape_wsse_authentication.encoder.'.$firewallName;
        $passwordHasherDefinition = new ChildDefinition('escape_wsse_authentication.encoder');

        if (isset($config['encoder']['algorithm'])) {
            $passwordHasherDefinition->replaceArgument(0, $config['encoder']['algorithm']);
        }

        if (isset($config['encoder']['encodeHashAsBase64'])) {
            $passwordHasherDefinition->replaceArgument(1, $config['encoder']['encodeHashAsBase64']);
        }

        if (isset($config['encoder']['iterations'])) {
            $passwordHasherDefinition->replaceArgument(2, $config['encoder']['iterations']);
        }

        $container->setDefinition($passwordHasherId, $passwordHasherDefinition);

        $authenticator_config = array_intersect_key($config, $this->options);

        $authenticatorDefinition = $container->setDefinition($authenticatorId, new ChildDefinition('escape_wsse_authentication.authenticator'));

        $authenticatorDefinition
            ->replaceArgument('$userProvider', new Reference($userProviderId))
            ->replaceArgument('$passwordHasher', new Reference($passwordHasherId))
            ->replaceArgument('$failureHandler', new Reference($this->createAuthenticationFailureHandler($container, $firewallName, $config)))
            ->replaceArgument('$options', $authenticator_config)
        ;

        if ($authenticator_config['nonce_cache_service']) {
            $authenticatorDefinition->replaceArgument('$nonceCache', new Reference($authenticator_config['nonce_cache_service']));
        }

        return $authenticatorId;
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
