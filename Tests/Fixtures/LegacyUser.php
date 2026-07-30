<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user exposing only the pre-5.3 API: it has getUsername(), but no getUserIdentifier().
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
