<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection;

use Escape\WSSEAuthenticationBundle\DependencyInjection\Configuration;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;

class ConfigurationTest extends TestCase
{
    /**
     * NOTE: "app.cache" is asserted because that is what the bundle currently
     * defaults to; Symfony's own cache pool is called "cache.app", so any
     * application that does not override this option cannot compile.
     */
    public function testDefaults()
    {
        $config = (new Processor())->processConfiguration(new Configuration(), []);

        $this->assertSame(
            [
                'authentication_encoder_class' => MessageDigestPasswordHasher::class,
                'nonce_cache_service' => 'app.cache',
            ],
            $config
        );
    }

    public function testOverrides()
    {
        $config = (new Processor())->processConfiguration(new Configuration(), [
            [
                'authentication_encoder_class' => 'App\Security\CustomHasher',
                'nonce_cache_service' => 'cache.app',
            ],
        ]);

        $this->assertSame(
            [
                'authentication_encoder_class' => 'App\Security\CustomHasher',
                'nonce_cache_service' => 'cache.app',
            ],
            $config
        );
    }
}
