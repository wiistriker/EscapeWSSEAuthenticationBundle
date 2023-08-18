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

          if (method_exists($extension, 'addAuthenticatorFactory')) {
              $extension->addAuthenticatorFactory(new WSSEFactory());
          } else {
              $extension->addSecurityListenerFactory(new Factory());
          }
      }
}
