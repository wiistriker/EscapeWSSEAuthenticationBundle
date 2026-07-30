<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\Authenticator;

use Escape\WSSEAuthenticationBundle\Security\Http\Authenticator\WSSEAuthenticator;
use Escape\WSSEAuthenticationBundle\Tests\Fixtures\LegacyUser;
use Escape\WSSEAuthenticationBundle\Tests\Fixtures\ModernUser;
use Escape\WSSEAuthenticationBundle\Tests\Fixtures\ModernUserProvider;
use Escape\WSSEAuthenticationBundle\Tests\Fixtures\WSSEUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class WSSEAuthenticatorTest extends TestCase
{
    private const DATE_FORMAT = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

    private const REALM = 'somerealm';
    private const PROFILE = 'someprofile';

    private ArrayAdapter $nonceCache;

    protected function setUp(): void
    {
        $this->nonceCache = new ArrayAdapter();
    }

    /**
     * @dataProvider provideSupports
     */
    public function testSupports(Request $request, ?bool $expected)
    {
        $this->assertSame($expected, $this->createAuthenticator($this->createLegacyProvider())->supports($request));
    }

    public function provideSupports(): array
    {
        return [
            'no X-WSSE header, GET' => [Request::create('/'), false],
            'no X-WSSE header, POST' => [Request::create('/foo', 'POST'), false],
            'complete X-WSSE header' => [
                Request::create('/', 'GET', [], [], [], [
                    'HTTP_X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'
                ]),
                true
            ],
            'malformed X-WSSE header' => [
                Request::create('/', 'GET', [], [], [], [
                    'HTTP_X-WSSE' => 'UsernameToken2 Usern_ame="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'
                ]),
                false
            ],
        ];
    }

    public function testAuthenticateWithLegacyProviderAndUser()
    {
        $user = new LegacyUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator($this->createLegacyProvider($user));

        $created = gmdate(DATE_ATOM);
        $request = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($request));

        $passport = $authenticator->authenticate($request);

        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $this->assertSame($user, $passport->getUser());
    }

    public function testAuthenticateWithModernProviderAndUser()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $created = gmdate(DATE_ATOM);
        $request = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($request));
        $this->assertSame($user, $authenticator->authenticate($request)->getUser());
    }

    public function testAuthenticateUsesWSSECredentialsWhenUserImplementsWSSEUserInterface()
    {
        $user = new WSSEUser('someuser', 'wsse-secret', 'wsse-salt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $created = gmdate(DATE_ATOM);
        $request = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'wsse-secret', 'wsse-salt'));

        $this->assertTrue($authenticator->supports($request));
        $this->assertSame($user, $authenticator->authenticate($request)->getUser());
    }

    public function testAuthenticateDecodesUsernameWhenEncodedHeaderIsPresent()
    {
        $user = new ModernUser('some@user', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['some@user' => $user]));

        $created = gmdate(DATE_ATOM);
        $request = $this->createWSSERequest(
            'some%40user',
            'somenonce',
            $created,
            $this->digest('somenonce', $created, 'somesecret', 'somesalt'),
            ['X-WSSE-Username-Encoded' => '1']
        );

        $this->assertTrue($authenticator->supports($request));
        $this->assertSame($user, $authenticator->authenticate($request)->getUser());
    }

    public function testAuthenticateThrowsWhenUserIsNotFound()
    {
        $authenticator = $this->createAuthenticator(new ModernUserProvider());

        $created = gmdate(DATE_ATOM);
        $request = $this->createWSSERequest('nobody', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($request));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('WSSE authentication failed.');

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsOnInvalidDigest()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $request = $this->createWSSERequest('someuser', 'somenonce', gmdate(DATE_ATOM), 'definitely-not-the-right-digest');

        $this->assertTrue($authenticator->supports($request));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('WSSE authentication failed.');

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsOnReusedNonce()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $created = gmdate(DATE_ATOM);
        $first = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($first));
        $this->assertSame($user, $authenticator->authenticate($first)->getUser());

        $created = gmdate(DATE_ATOM);
        $second = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($second));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Previously used nonce detected.');

        $authenticator->authenticate($second);
    }

    public function testAuthenticateThrowsOnMalformedCreated()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $request = $this->createWSSERequest('someuser', 'somenonce', 'not-a-timestamp', 'somedigest');

        $this->assertTrue($authenticator->supports($request));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Incorrectly formatted "created" in token.');

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsOnTokenFromTheFuture()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(new ModernUserProvider(['someuser' => $user]));

        $created = gmdate(DATE_ATOM, time() + 300);
        $request = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($request));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Future token detected.');

        $authenticator->authenticate($request);
    }

    /**
     * NOTE: "future_allowed_seconds" has to be raised above "lifetime" for this
     * branch to be reachable at all. isTokenFromFuture() compares abs($delta),
     * so with the defaults (61 vs 300) every token older than 61 seconds is
     * rejected as "Future token detected." before the lifetime check runs.
     * Once that is fixed, this test should be reduced to plain defaults.
     */
    public function testAuthenticateThrowsOnExpiredToken()
    {
        $user = new ModernUser('someuser', 'somesecret', 'somesalt');
        $authenticator = $this->createAuthenticator(
            new ModernUserProvider(['someuser' => $user]),
            ['lifetime' => 300, 'future_allowed_seconds' => 100000]
        );

        $created = gmdate(DATE_ATOM, time() - 400);
        $request = $this->createWSSERequest('someuser', 'somenonce', $created, $this->digest('somenonce', $created, 'somesecret', 'somesalt'));

        $this->assertTrue($authenticator->supports($request));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Token has expired.');

        $authenticator->authenticate($request);
    }

    public function testOnAuthenticationSuccessReturnsNull()
    {
        $this->assertNull(
            $this->createAuthenticator($this->createLegacyProvider())->onAuthenticationSuccess(
                Request::create('/'),
                $this->createMock(TokenInterface::class),
                'somefirewall'
            )
        );
    }

    public function testOnAuthenticationFailureReturnsNullWithoutHandler()
    {
        $this->assertNull(
            $this->createAuthenticator($this->createLegacyProvider())->onAuthenticationFailure(
                Request::create('/'),
                new AuthenticationException()
            )
        );
    }

    public function testOnAuthenticationFailureDelegatesToHandler()
    {
        $request = Request::create('/');
        $exception = new AuthenticationException();
        $response = new Response('handled', Response::HTTP_FORBIDDEN);

        $handler = $this->createMock(AuthenticationFailureHandlerInterface::class);
        $handler->expects($this->once())
            ->method('onAuthenticationFailure')
            ->with($request, $exception)
            ->willReturn($response);

        $authenticator = $this->createAuthenticator($this->createLegacyProvider(), [], $handler);

        $this->assertSame($response, $authenticator->onAuthenticationFailure($request, $exception));
    }

    public function testStart()
    {
        $response = $this->createAuthenticator($this->createLegacyProvider())->start(Request::create('/'));

        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertSame(
            sprintf('WSSE realm="%s", profile="%s"', self::REALM, self::PROFILE),
            $response->headers->get('WWW-Authenticate')
        );
    }

    public function testGetDateFormat()
    {
        $this->assertSame(self::DATE_FORMAT, $this->createAuthenticator($this->createLegacyProvider())->getDateFormat());
    }

    private function createAuthenticator(
        UserProviderInterface $userProvider,
        array $options = [],
        ?AuthenticationFailureHandlerInterface $failureHandler = null
    ): WSSEAuthenticator {
        return new WSSEAuthenticator(
            $userProvider,
            new MessageDigestPasswordHasher('sha1', true, 1),
            $this->nonceCache,
            $failureHandler,
            array_merge([
                'realm' => self::REALM,
                'profile' => self::PROFILE,
                'lifetime' => 300,
                'date_format' => self::DATE_FORMAT,
            ], $options)
        );
    }

    /**
     * A mock of UserProviderInterface has no loadUserByIdentifier() - that method
     * only exists as a @method annotation on the 5.4 interface - so the
     * authenticator falls back to loadUserByUsername().
     */
    private function createLegacyProvider(?UserInterface $user = null): UserProviderInterface
    {
        $provider = $this->createMock(UserProviderInterface::class);

        if (null !== $user) {
            $provider->expects($this->once())->method('loadUserByUsername')->willReturn($user);
        }

        return $provider;
    }

    private function digest(string $nonce, string $created, string $secret, string $salt): string
    {
        return (new MessageDigestPasswordHasher('sha1', true, 1))->hash(
            sprintf('%s%s%s', base64_decode($nonce), $created, $secret),
            $salt
        );
    }

    private function createWSSERequest(string $username, string $nonce, string $created, string $digest, array $headers = []): Request
    {
        $server = [
            'HTTP_X-WSSE' => sprintf(
                'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"',
                $username,
                $digest,
                $nonce,
                $created
            ),
        ];

        foreach ($headers as $name => $value) {
            $server['HTTP_'.$name] = $value;
        }

        return Request::create('/', 'GET', [], [], [], $server);
    }
}
