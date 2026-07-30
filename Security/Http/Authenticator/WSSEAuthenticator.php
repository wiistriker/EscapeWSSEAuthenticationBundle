<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Authenticator;

use Escape\WSSEAuthenticationBundle\Security\Core\User\WSSEUserInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\LegacyPasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\LegacyPasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use UnexpectedValueException;

class WSSEAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    protected UserProviderInterface $userProvider;
    protected LegacyPasswordHasherInterface $passwordHasher;
    protected CacheItemPoolInterface $nonceCache;
    protected ?AuthenticationFailureHandlerInterface $failureHandler;
    protected array $options;

    public function __construct(
        UserProviderInterface $userProvider,
        LegacyPasswordHasherInterface $passwordHasher,
        CacheItemPoolInterface $nonceCache,
        ?AuthenticationFailureHandlerInterface $failureHandler,
        array $options
    ) {
        $this->userProvider = $userProvider;
        $this->passwordHasher = $passwordHasher;
        $this->nonceCache = $nonceCache;
        $this->failureHandler = $failureHandler;
        $this->options = array_merge([
            'future_allowed_seconds' => 61
        ], $options);
    }

    public function supports(Request $request): ?bool
    {
        return null !== $this->getWSSEHeader($request);
    }

    public function authenticate(Request $request): Passport
    {
        $wsseHeader = $this->getWSSEHeader($request);
        if (null === $wsseHeader) {
            throw new BadCredentialsException('WSSE authentication failed.');
        }

        try {
            if (method_exists($this->userProvider, 'loadUserByIdentifier')) {
                $user = $this->userProvider->loadUserByIdentifier($wsseHeader['Username']);
            } else {
                $user = $this->userProvider->loadUserByUsername($wsseHeader['Username']);
            }
        } catch (UserNotFoundException $e) {
            throw new BadCredentialsException('WSSE authentication failed.');
        }

        if ($this->validateDigest(
            $wsseHeader['PasswordDigest'],
            $wsseHeader['Nonce'],
            $wsseHeader['Created'],
            $this->getSecret($user),
            $this->getSalt($user)
        )) {
            //getUserIdentifier() does not exist before Symfony 5.3, getUsername()
            //is gone from 6.0 on - so neither can be called unconditionally
            if (method_exists($user, 'getUserIdentifier')) {
                return new SelfValidatingPassport(
                    new UserBadge($user->getUserIdentifier(), static function () use ($user) { return $user; })
                );
            }

            return new SelfValidatingPassport(
                new UserBadge($user->getUsername(), static function () use ($user) { return $user; })
            );
        }

        throw new BadCredentialsException('WSSE authentication failed.');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if (!$this->failureHandler) {
            return null;
        }

        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    /**
     * This method returns the value of a bit header by the key
     * @throws UnexpectedValueException
     */
    private function parseWSSEHeaderValue(string $wsseHeader, string $key): string
    {
        if (!preg_match('/'.$key.'="([^"]+)"/', $wsseHeader, $matches)) {
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
    protected function parseWSSEHeader(string $wsseHeader): ?array
    {
        try {
            $result = [
                'Username' => $this->parseWSSEHeaderValue($wsseHeader, 'Username'),
                'PasswordDigest' => $this->parseWSSEHeaderValue($wsseHeader, 'PasswordDigest'),
                'Nonce' => $this->parseWSSEHeaderValue($wsseHeader, 'Nonce'),
                'Created' => $this->parseWSSEHeaderValue($wsseHeader, 'Created')
            ];
        } catch (UnexpectedValueException $e) {
            return null;
        }

        return $result;
    }

    /**
     * Reads and parses the credentials carried by the request, or null when the
     * request carries no usable X-WSSE header.
     *
     * This is deliberately derived from the request on every call rather than
     * cached on the authenticator: the authenticator is a shared service, so
     * state kept here would leak between sub-requests, between firewalls and -
     * in a worker runtime - between requests.
     */
    protected function getWSSEHeader(Request $request): ?array
    {
        $wsseHeader = $request->headers->get('X-WSSE');
        if (null === $wsseHeader) {
            return null;
        }

        $wsseHeader = $this->parseWSSEHeader($wsseHeader);
        if (null === $wsseHeader) {
            return null;
        }

        if ($request->headers->has('X-WSSE-Username-Encoded')) {
            $wsseHeader['Username'] = urldecode($wsseHeader['Username']);
        }

        return $wsseHeader;
    }

    protected function isFormattedCorrectly($created): bool
    {
        return 1 === preg_match($this->getDateFormat(), $created);
    }

    /**
     * Tokens dated slightly ahead of us are tolerated to absorb clock skew
     * between client and server. Note that this must not use abs(): tokens from
     * the past are the lifetime check's business, not this one's.
     */
    protected function isTokenFromFuture($created): bool
    {
        return strtotime($created) - strtotime($this->getCurrentTime()) > $this->options['future_allowed_seconds'];
    }

    protected function getCurrentTime(): string
    {
        return gmdate(DATE_ATOM);
    }

    /**
     * UserInterface declares getPassword() only up to Symfony 6; from 7 on the
     * password lives on PasswordAuthenticatedUserInterface, so it cannot be
     * called unconditionally.
     */
    protected function getSecret(UserInterface $user): string
    {
        if ($user instanceof WSSEUserInterface) {
            return $user->getWSSESecret();
        }

        if ($user instanceof PasswordAuthenticatedUserInterface || method_exists($user, 'getPassword')) {
            return $user->getPassword() ?? '';
        }

        // @codeCoverageIgnoreStart
        // Unreachable on Symfony 5.4/6.x, where UserInterface still requires
        // getPassword(); only a Symfony 7 user class can end up here.
        throw new UnexpectedValueException(sprintf(
            'Cannot read a WSSE secret from "%s": it must implement "%s" or "%s".',
            get_class($user),
            WSSEUserInterface::class,
            PasswordAuthenticatedUserInterface::class
        ));
        // @codeCoverageIgnoreEnd
    }

    /**
     * An empty salt is legitimate - unlike the secret, a user without one can
     * still authenticate - so this falls back to '' rather than failing.
     */
    protected function getSalt(UserInterface $user): string
    {
        if ($user instanceof WSSEUserInterface) {
            return $user->getWSSESalt();
        }

        if ($user instanceof LegacyPasswordAuthenticatedUserInterface || method_exists($user, 'getSalt')) {
            return $user->getSalt() ?? '';
        }

        // @codeCoverageIgnoreStart
        // Unreachable on Symfony 5.4/6.x, where UserInterface still requires getSalt().
        return '';
        // @codeCoverageIgnoreEnd
    }

    public function getDateFormat(): string
    {
        return $this->options['date_format'];
    }

    protected function validateDigest(string $digest, string $nonce, string $created, string $secret, string $salt): bool
    {
        //check whether timestamp is formatted correctly
        if (!$this->isFormattedCorrectly($created)) {
            throw new CustomUserMessageAuthenticationException('Incorrectly formatted "created" in token.');
        }

        //check whether timestamp is not in the future
        if ($this->isTokenFromFuture($created)) {
            throw new CustomUserMessageAuthenticationException('Future token detected.');
        }

        //expire timestamp after specified lifetime
        if (strtotime($this->getCurrentTime()) - strtotime($created) > $this->options['lifetime']) {
            throw new CustomUserMessageAuthenticationException('Token has expired.');
        }

        $nonceCacheItem = $this->nonceCache->getItem('wsse_nonce_' . hash('sha256', $nonce));
        if ($nonceCacheItem->isHit()) {
            throw new CustomUserMessageAuthenticationException('Previously used nonce detected.');
        }

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

        if (!hash_equals($expected, $digest)) {
            return false;
        }

        //only burn the nonce once the request proved to be genuine, so that
        //unauthenticated traffic cannot fill the cache pool
        $nonceCacheItem
            ->set(strtotime($this->getCurrentTime()))
            ->expiresAfter($this->options['lifetime'])
        ;

        $this->nonceCache->save($nonceCacheItem);

        return true;
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED, [
            'WWW-Authenticate' => sprintf(
                'WSSE realm="%s", profile="%s"',
                $this->options['realm'],
                $this->options['profile']
            )
        ]);
    }
}
