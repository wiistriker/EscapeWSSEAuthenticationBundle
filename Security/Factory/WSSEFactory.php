<?php

namespace Escape\WSSEAuthenticationBundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Deliberately implements AuthenticatorFactoryInterface directly instead of
 * extending AbstractFactory: the latter carries the removed legacy
 * authentication system on 5.4 and has a different shape on 6.x/7.x.
 */
class WSSEFactory implements AuthenticatorFactoryInterface
{
    public const PRIORITY = 0;

    /**
     * ISO8601, see http://www.pelagodesign.com/blog/2009/05/20/iso-8601-date-validation-that-doesnt-suck/
     */
    public const DEFAULT_DATE_FORMAT = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

    /**
     * Firewall options forwarded to the authenticator; everything else in the
     * configuration is consumed while building the container.
     */
    private const AUTHENTICATOR_OPTIONS = [
        'realm',
        'profile',
        'lifetime',
        'date_format',
        'future_allowed_seconds',
    ];

    public function getKey(): string
    {
        return 'wsse';
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
                ->scalarNode('provider')->end()
                ->scalarNode('realm')->defaultNull()->end()
                ->scalarNode('profile')->defaultValue('_password')->end()
                ->integerNode('lifetime')->defaultValue(300)->end()
                ->scalarNode('date_format')->defaultValue(self::DEFAULT_DATE_FORMAT)->end()
                ->integerNode('future_allowed_seconds')->defaultValue(61)->end()
                ->scalarNode('nonce_cache_service')->defaultNull()->end()
                ->scalarNode('failure_handler')->defaultNull()->end()
                ->arrayNode('encoder')
                    ->children()
                        ->scalarNode('algorithm')->end()
                        ->booleanNode('encodeHashAsBase64')->end()
                        ->integerNode('iterations')->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
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

        $authenticatorId = 'security.authenticator.wsse.'.$firewallName;
        $authenticatorDefinition = $container->setDefinition(
            $authenticatorId,
            new ChildDefinition('escape_wsse_authentication.authenticator')
        );

        $authenticatorDefinition
            ->replaceArgument('$userProvider', new Reference($userProviderId))
            ->replaceArgument('$passwordHasher', new Reference($passwordHasherId))
            ->replaceArgument('$options', array_intersect_key($config, array_flip(self::AUTHENTICATOR_OPTIONS)))
        ;

        // Only wire a failure handler when the firewall asks for one. The default
        // handler redirects to a login path and touches the session, which cannot
        // work on the stateless firewalls WSSE targets and would suppress the 401
        // challenge produced by the entry point.
        $authenticatorDefinition->replaceArgument(
            '$failureHandler',
            isset($config['failure_handler']) ? new Reference($config['failure_handler']) : null
        );

        if (isset($config['nonce_cache_service'])) {
            $authenticatorDefinition->replaceArgument('$nonceCache', new Reference($config['nonce_cache_service']));
        }

        return $authenticatorId;
    }
}
