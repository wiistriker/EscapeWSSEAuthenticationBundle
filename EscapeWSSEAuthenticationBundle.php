<?php

namespace Escape\WSSEAuthenticationBundle;

use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;

class EscapeWSSEAuthenticationBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addAuthenticatorFactory(new WSSEFactory());
    }
}
