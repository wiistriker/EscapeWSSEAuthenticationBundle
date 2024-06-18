<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Authenticator;

use Escape\WSSEAuthenticationBundle\Security\Core\User\WSSEUserInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
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
    protected PasswordHasherInterface $passwordHasher;
    protected CacheItemPoolInterface $nonceCache;
    protected ?AuthenticationFailureHandlerInterface $failureHandler;
    protected array $options;

    protected ?array $wsse_header = null;

    public function __construct(
        UserProviderInterface $userProvider,
        PasswordHasherInterface $passwordHasher,
        CacheItemPoolInterface $nonceCache,
        ?AuthenticationFailureHandlerInterface $failureHandler,
        array $options
    ) {
        $this->userProvider = $userProvider;
        $this->passwordHasher = $passwordHasher;
        $this->nonceCache = $nonceCache;
        $this->failureHandler = $failureHandler;
        $this->options = $options;
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
     * @return Passport
     */
    public function authenticate(Request $request)
    {
        try {
            if (method_exists($this->userProvider, 'loadUserByIdentifier')) {
                $user = $this->userProvider->loadUserByIdentifier($this->wsse_header['Username']);
            } else {
                $user = $this->userProvider->loadUserByUsername($this->wsse_header['Username']);
            }
        } catch (UserNotFoundException $e) {
            throw new BadCredentialsException('WSSE authentication failed.');
        }

        if ($this->validateDigest(
            $this->wsse_header['PasswordDigest'],
            $this->wsse_header['Nonce'],
            $this->wsse_header['Created'],
            $this->getSecret($user),
            $this->getSalt($user)
        )) {
            if (method_exists($user, 'getUserIdentifier')) {
                return new SelfValidatingPassport(
                    new UserBadge($user->getUserIdentifier(), static function () use ($user) { return $user; })
                );
            } else {
                return new SelfValidatingPassport(
                    new UserBadge($user->getUsername(), static function () use ($user) { return $user; })
                );
            }
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
        try {
            $result = [
                'Username' => $this->parseWSSEHeaderValue($wsse_header, 'Username'),
                'PasswordDigest' => $this->parseWSSEHeaderValue($wsse_header, 'PasswordDigest'),
                'Nonce' => $this->parseWSSEHeaderValue($wsse_header, 'Nonce'),
                'Created' => $this->parseWSSEHeaderValue($wsse_header, 'Created')
            ];
        } catch (UnexpectedValueException $e) {
            return null;
        }

        return $result;
    }

    protected function isFormattedCorrectly($created): bool
    {
        return preg_match($this->getDateFormat(), $created);
    }

    protected function isTokenFromFuture($created): bool
    {
        return abs(strtotime($created) - strtotime($this->getCurrentTime())) > 61;
    }

    protected function getCurrentTime(): string
    {
        return gmdate(DATE_ATOM);
    }

    protected function getSecret(UserInterface $user): string
    {
        if ($user instanceof WSSEUserInterface) {
            return $user->getWSSESecret();
        }

        return $user->getPassword() ?? '';
    }

    protected function getSalt(UserInterface $user): string
    {
        if ($user instanceof WSSEUserInterface) {
            return $user->getWSSESalt();
        }

        return $user->getSalt() ?? '';
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

        $nonceCacheItem = $this->nonceCache->getItem(md5($nonce));
        if ($nonceCacheItem->isHit()) {
            throw new CustomUserMessageAuthenticationException('Previously used nonce detected.');
        }

        $nonceCacheItem
            ->set(strtotime($this->getCurrentTime()))
            ->expiresAfter($this->options['lifetime'])
        ;

        $this->nonceCache->save($nonceCacheItem);

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

    /**
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
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
