<?php

namespace Escape\WSSEAuthenticationBundle;

use Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class EscapeWSSEAuthenticationBundle extends Bundle
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addAuthenticatorFactory(new WSSEFactory());
    }
}
