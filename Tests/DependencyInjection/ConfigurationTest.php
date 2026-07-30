<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection;

use Escape\WSSEAuthenticationBundle\DependencyInjection\Configuration;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;

class ConfigurationTest extends TestCase
{
    public function testDefaults()
    {
        $config = (new Processor())->processConfiguration(new Configuration(), []);

        $this->assertSame(
            [
                'authentication_encoder_class' => MessageDigestPasswordHasher::class,
                'nonce_cache_service' => 'cache.app',
            ],
            $config
        );
    }

    public function testOverrides()
    {
        $config = (new Processor())->processConfiguration(new Configuration(), [
            [
                'authentication_encoder_class' => 'App\Security\CustomHasher',
                'nonce_cache_service' => 'app.wsse_nonce_cache',
            ],
        ]);

        $this->assertSame(
            [
                'authentication_encoder_class' => 'App\Security\CustomHasher',
                'nonce_cache_service' => 'app.wsse_nonce_cache',
            ],
            $config
        );
    }
}
