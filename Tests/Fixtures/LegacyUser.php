<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user exposing only the pre-5.3 API: it has getUsername(), but no
 * getUserIdentifier().
 *
 * WARNING: loadable on Symfony 5.4 only. From 6.0 on UserInterface declares
 * getUserIdentifier() for real, so declaring this class is a fatal error - it
 * must never be referenced without guarding on
 * method_exists(UserInterface::class, 'getUserIdentifier') first, and nothing
 * else in the fixtures may extend it.
 */
class LegacyUser implements UserInterface
{
    private string $username;
    private ?string $password;
    private ?string $salt;

    public function __construct(string $username, ?string $password = null, ?string $salt = null)
    {
        $this->username = $username;
        $this->password = $password;
        $this->salt = $salt;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function getSalt(): ?string
    {
        return $this->salt;
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function eraseCredentials(): void
    {
    }
}
