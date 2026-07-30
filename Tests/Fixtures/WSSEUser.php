<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Fixtures;

use Escape\WSSEAuthenticationBundle\Security\Core\User\WSSEUserInterface;

/**
 * A user carrying WSSE credentials separate from its login password; the
 * password/salt below are deliberately wrong so a test fails if the
 * authenticator falls back to them.
 */
class WSSEUser extends ModernUser implements WSSEUserInterface
{
    private string $wsseSecret;
    private string $wsseSalt;

    public function __construct(string $username, string $wsseSecret, string $wsseSalt)
    {
        parent::__construct($username, 'not-the-wsse-secret', 'not-the-wsse-salt');

        $this->wsseSecret = $wsseSecret;
        $this->wsseSalt = $wsseSalt;
    }

    public function getWSSESecret(): string
    {
        return $this->wsseSecret;
    }

    public function getWSSESalt(): string
    {
        return $this->wsseSalt;
    }
}
