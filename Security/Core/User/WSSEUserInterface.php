<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\User;

interface WSSEUserInterface
{
    public function getWSSESecret(): string;
    public function getWSSESalt(): string;
}
