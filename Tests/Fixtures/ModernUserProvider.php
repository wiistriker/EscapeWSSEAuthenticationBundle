<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * A provider exposing the 5.3+ API: loadUserByIdentifier() is a real method, so
 * the authenticator takes the non-legacy branch.
 */
class ModernUserProvider implements UserProviderInterface
{
    /**
     * @var array<string, UserInterface>
     */
    private array $users;

    /**
     * @param array<string, UserInterface> $users indexed by identifier
     */
    public function __construct(array $users = [])
    {
        $this->users = $users;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        if (!isset($this->users[$identifier])) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier));
        }

        return $this->users[$identifier];
    }

    public function loadUserByUsername(string $username): UserInterface
    {
        return $this->loadUserByIdentifier($username);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return is_a($class, UserInterface::class, true);
    }
}
