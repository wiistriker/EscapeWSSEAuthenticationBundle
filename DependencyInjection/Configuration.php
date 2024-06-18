<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('escape_wsse_authentication');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('authentication_encoder_class')->defaultValue(MessageDigestPasswordHasher::class)->end()
            ->end();

        return $treeBuilder;
    }
}