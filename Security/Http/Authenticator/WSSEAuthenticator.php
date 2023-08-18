<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Authenticator;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class WSSEAuthenticator extends AbstractAuthenticator
{
    protected UserProviderInterface $userProvider;
    protected PasswordHasherInterface $passwordHasher;
    protected array $options;
    protected int $token_lifetime;
    protected string $date_format;

    protected ?array $wsse_header = null;

    public function __construct(
        UserProviderInterface $userProvider,
        PasswordHasherInterface $passwordHasher,
        array $options,
        int $token_lifetime = 300,
        string $date_format = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
    ) {
        $this->userProvider = $userProvider;
        $this->passwordHasher = $passwordHasher;
        $this->options = $options;
        $this->token_lifetime = $token_lifetime;
        $this->date_format = $date_format;
    }

    public function supports(Request $request): ?bool
    {
        if (!$request->headers->has('X-WSSE')) {
            return false;
        }

        $wsse_header = $this->parseWSSEHeader($request->headers->get('X-WSSE'));
        if (!$wsse_header) {
            return false;
        }

        $this->wsse_header = $wsse_header;

        return true;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(Request $request)
    {
        try {
            $user = $this->userProvider->loadUserByIdentifier($this->wsse_header['Username']);
        } catch (UserNotFoundException $e) {
            throw new AuthenticationException('WSSE authentication failed.');
        }

        if ($this->validateDigest(
            $this->wsse_header['PasswordDigest'],
            $this->wsse_header['Nonce'],
            $this->wsse_header['Created'],
            $this->getSecret($user),
            $this->getSalt($user)
        )) {
            return new SelfValidatingPassport(
                new UserBadge($user->getUserIdentifier(), static function () use ($user) { return $user; })
            );
        }

        throw new AuthenticationException('WSSE authentication failed.');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new Response('', 403);
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    /**
     * This method returns the value of a bit header by the key
     * @throws UnexpectedValueException
     */
    private function parseWSSEHeaderValue(string $wsse_header, string $key): string
    {
        if (!preg_match('/'.$key.'="([^"]+)"/', $wsse_header, $matches)) {
            throw new UnexpectedValueException('The string was not found');
        }

        return $matches[1];
    }

    /**
     * This method parses the X-WSSE header
     *
     * If Username, PasswordDigest, Nonce and Created exist then it returns their value,
     * otherwise the method returns null.
     */
    protected function parseWSSEHeader(string $wsse_header): ?array
    {
        $result = [];

        try {
            $result = [
                'Username' => $this->parseWSSEHeaderValue($wsse_header, 'Username'),
                'PasswordDigest' => $this->parseWSSEHeaderValue($wsse_header, 'PasswordDigest'),
                'Nonce' => $this->parseWSSEHeaderValue($wsse_header, 'Nonce'),
                'Created' => $this->parseWSSEHeaderValue($wsse_header, 'Created')
            ];
        } catch(UnexpectedValueException $e) {
            return null;
        }

        return $result;
    }

    protected function isFormattedCorrectly($created)
    {
        return preg_match($this->getDateFormat(), $created);
    }

    protected function isTokenFromFuture($created)
    {
        return strtotime($created) > strtotime($this->getCurrentTime());
    }

    protected function getCurrentTime()
    {
        return gmdate(DATE_ISO8601);
    }

    protected function getSecret(UserInterface $user): string
    {
        return $user->getApiToken() ?? '';
    }

    protected function getSalt(UserInterface $user): string
    {
        return '';
        return $user->getSalt() ?? '';
    }

    public function getDateFormat(): string
    {
        return $this->date_format;
    }

    protected function validateDigest(string $digest, string $nonce, string $created, string $secret, string $salt): bool
    {
        //check whether timestamp is formatted correctly
        if (!$this->isFormattedCorrectly($created)) {
            throw new BadCredentialsException('Incorrectly formatted "created" in token.');
        }

        //check whether timestamp is not in the future
        if ($this->isTokenFromFuture($created)) {
            throw new BadCredentialsException('Future token detected.');
        }

        //expire timestamp after specified lifetime
        if (strtotime($this->getCurrentTime()) - strtotime($created) > $this->token_lifetime) {
            throw new CredentialsExpiredException('Token has expired.');
        }

//        //validate that nonce is unique within specified lifetime
//        //if it is not, this could be a replay attack
//        if ($this->nonceCache->contains($nonce)) {
//            throw new NonceExpiredException('Previously used nonce detected.');
//        }
//
//        $this->nonceCache->save($nonce, strtotime($this->getCurrentTime()), $this->token_lifetime);

        //validate secret
        $expected = $this->passwordHasher->hash(
            sprintf(
                '%s%s%s',
                base64_decode($nonce),
                $created,
                $secret
            ),
            $salt
        );

        return hash_equals($expected, $digest);
    }
}
