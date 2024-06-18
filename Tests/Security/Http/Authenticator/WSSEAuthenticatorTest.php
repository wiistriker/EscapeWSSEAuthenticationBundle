<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\Authenticator;

use Escape\WSSEAuthenticationBundle\Security\Http\Authenticator\WSSEAuthenticator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class WSSEAuthenticatorTest extends TestCase
{
    private ?UserProviderInterface $userProvider = null;
    private ?AdapterInterface $cacheAdapter = null;
    private ?WSSEAuthenticator $authenticator = null;
    private ?UserInterface $user = null;

    protected function setUp(): void
    {
        $this->userProvider = $this->createMock(UserProviderInterface::class);
        $this->cacheAdapter = new ArrayAdapter();

        $realm = 'somerealm';
        $profile = 'someprofile';
        $lifetime = 300;
        $date_format = '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/';

        $this->authenticator = new WSSEAuthenticator($this->userProvider, new MessageDigestPasswordHasher('sha1', true, 1), $this->cacheAdapter, null, [
            'date_format' => $date_format,
            'lifetime' => $lifetime,
            'realm' => $realm,
            'profile' => $profile
        ]);

        $this->user = $this->createMock(UserInterface::class);
    }

    /**
     * @dataProvider provideSupports
     */
    public function testsSupports(Request $request, ?bool $expected)
    {
        $this->assertEquals($this->authenticator->supports($request), $expected);
    }

    public function provideSupports(): array
    {
        $requestGETWithoutWSSEHeader = Request::create('/');
        $requestPOSTWithoutWSSEHeader = Request::create('/foo', 'POST');

        $requestGET = Request::create('/', 'GET', [], [], [], [
            'HTTP_X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'
        ]);

        $requestGETWithMailformedHeader = Request::create('/', 'GET', [], [], [], [
            'HTTP_X-WSSE' => 'UsernameToken2 Usern_ame="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'
        ]);

        return [
            [ $requestGETWithoutWSSEHeader, false ],
            [ $requestPOSTWithoutWSSEHeader, false ],
            [ $requestGET, true ],
            [ $requestGETWithMailformedHeader, false ],
        ];
    }

    public function testAuthenticate()
    {
        $this->user->expects($this->once())->method('getUsername')->will($this->returnValue('someuser'));
        $this->user->expects($this->once())->method('getPassword')->will($this->returnValue('somesecret'));
        $this->user->expects($this->once())->method('getSalt')->will($this->returnValue('somesalt'));
        $this->userProvider->expects($this->once())->method('loadUserByUsername')->will($this->returnValue($this->user));

        $passwordHasher = new MessageDigestPasswordHasher('sha1', true, 1);
        $time = date(DATE_ISO8601);

        $digest = $passwordHasher->hash(
            sprintf(
                '%s%s%s',
                base64_decode('somenonce'),
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="' . $digest . '", Nonce="somenonce", Created="' . $time . '"'
        ]);

        $this->assertTrue($this->authenticator->supports($request));

        $passport = $this->authenticator->authenticate($request);
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $this->assertEquals($passport->getUser(), $this->user);
    }

    public function testAuthenticateWithSameNonce()
    {
        $this->user->expects($this->once())->method('getUsername')->will($this->returnValue('someuser'));
        $this->user->expects($this->exactly(2))->method('getPassword')->will($this->returnValue('somesecret'));
        $this->user->expects($this->exactly(2))->method('getSalt')->will($this->returnValue('somesalt'));
        $this->userProvider->expects($this->exactly(2))->method('loadUserByUsername')->will($this->returnValue($this->user));

        $passwordHasher = new MessageDigestPasswordHasher('sha1', true, 1);
        $time = date(DATE_ISO8601);

        $digest = $passwordHasher->hash(
            sprintf(
                '%s%s%s',
                base64_decode('somenonce'),
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="' . $digest . '", Nonce="somenonce", Created="' . $time . '"'
        ]);

        $this->assertTrue($this->authenticator->supports($request));

        $passport = $this->authenticator->authenticate($request);
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $this->assertEquals($passport->getUser(), $this->user);

        $time = date(DATE_ISO8601);

        $digest = $passwordHasher->hash(
            sprintf(
                '%s%s%s',
                base64_decode('somenonce'),
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_X-WSSE' => 'UsernameToken Username="someuser", PasswordDigest="' . $digest . '", Nonce="somenonce", Created="' . $time . '"'
        ]);

        $this->assertTrue($this->authenticator->supports($request));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Previously used nonce detected.');

        $this->authenticator->authenticate($request);
    }

    public function testStart()
    {
        $response = $this->authenticator->start(Request::create('/'));

        $this->assertEquals(401, $response->getStatusCode());

        $this->assertMatchesRegularExpression(
            sprintf(
                '/^WSSE realm="%s", profile="%s"$/',
                'somerealm',
                'someprofile'
            ),
            $response->headers->get('WWW-Authenticate')
        );
    }
}
