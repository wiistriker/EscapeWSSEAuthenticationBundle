<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

use Symfony\Component\Security\Core\User\LegacyPasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user usable on every supported Symfony version: getUserIdentifier() is a real
 * method (mandatory from 7 on) and the credentials are reachable through
 * LegacyPasswordAuthenticatedUserInterface, while getUsername()/getPassword()/
 * getSalt() keep it a valid UserInterface implementation on 5.4.
 */
class ModernUser implements UserInterface, LegacyPasswordAuthenticatedUserInterface
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

    public function getUserIdentifier(): string
    {
        return $this->username;
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
