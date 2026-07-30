<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

/**
 * A user exposing the 5.3+ API: getUserIdentifier() is a real method, so the
 * authenticator takes the non-legacy branch.
 */
class ModernUser extends LegacyUser
{
    public function getUserIdentifier(): string
    {
        return $this->getUsername();
    }
}
