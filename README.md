# EscapeWSSEAuthenticationBundle

WSSE authentication for Symfony, built on the authenticator-based security system.

Supports Symfony 5.4, 6.4 and 7.x on PHP 8.0+.

## Installation

```sh
composer require escapestudios/wsse-authentication-bundle
```

Register the bundle in `config/bundles.php` (Symfony Flex does this for you):

```php
return [
    // ...
    Escape\WSSEAuthenticationBundle\EscapeWSSEAuthenticationBundle::class => ['all' => true],
];
```

## Quick start

`config/packages/security.yaml`:

```yaml
security:
    firewalls:
        wsse_secured:
            pattern: ^/api/
            stateless: true
            wsse:
                realm: "Secured with WSSE" # shown in the WWW-Authenticate challenge
                profile: "UsernameToken"   # shown in the WWW-Authenticate challenge
```

On Symfony 5.4 the authenticator system must also be switched on, unless it
already is:

```yaml
security:
    enable_authenticator_manager: true
```

That is enough. Requests without valid credentials get a `401` carrying
`WWW-Authenticate: WSSE realm="...", profile="..."`.

The digest a client has to send is:

```
base64_encode(sha1(base64_decode(nonce) . created . secret, true))
```

...sent as:

```
X-WSSE: UsernameToken Username="...", PasswordDigest="...", Nonce="...", Created="..."
```

where `Created` is an ISO8601 timestamp and `Nonce` is base64-encoded random bytes.

## Firewall options

| Option | Default | Description |
| --- | --- | --- |
| `realm` | `null` | Realm advertised in the `WWW-Authenticate` header. |
| `profile` | `_password` | Profile advertised in the `WWW-Authenticate` header. |
| `lifetime` | `300` | How long (seconds) a token stays valid after `Created`. |
| `future_allowed_seconds` | `61` | How far ahead of the server clock a `Created` timestamp may be, to absorb clock skew. |
| `date_format` | ISO8601 regex | Pattern the `Created` value must match. |
| `nonce_cache_service` | *(bundle default)* | PSR-6 pool used to store spent nonces. |
| `failure_handler` | `null` | Service id of an `AuthenticationFailureHandlerInterface`. Leave unset to get the `401` challenge. |
| `provider` | *(firewall default)* | User provider to use, when it differs from the firewall's. |
| `encoder` | sha1/base64/1 | Digest algorithm, see below. |

Do not set `failure_handler` unless you really want to take over the failure
response: without it, failures fall through to the entry point, which is what
produces the `401` challenge.

### Digest algorithm

```yaml
wsse:
    encoder:
        algorithm: sha1
        encodeHashAsBase64: true
        iterations: 1
```

:warning: sha1 with a single iteration is the WSSE default, not a secure choice.
Prefer a stronger algorithm if your clients can follow.

The configured class must implement `LegacyPasswordHasherInterface` — WSSE hashes
the secret together with an external salt, which the non-legacy hasher interface
does not support.

### Nonce cache

Spent nonces are stored in a PSR-6 pool so a captured request cannot be replayed
within its lifetime. By default the bundle uses `cache.app`; point it at a
dedicated pool if you would rather not share one:

```yaml
framework:
    cache:
        pools:
            app.wsse_nonce_cache:
                adapter: cache.adapter.redis

security:
    firewalls:
        wsse_secured:
            wsse:
                nonce_cache_service: app.wsse_nonce_cache
```

Entries expire on their own after `lifetime` seconds, so the pool needs no
housekeeping.

## Bundle-wide configuration

`config/packages/escape_wsse_authentication.yaml`:

```yaml
escape_wsse_authentication:
    authentication_encoder_class: Symfony\Component\PasswordHasher\Hasher\MessageDigestPasswordHasher
    nonce_cache_service: cache.app
```

Both values above are the defaults; `nonce_cache_service` here applies to every
firewall that does not set its own.

## Separate WSSE credentials

By default the digest is verified against the user's password and salt. Implement
`WSSEUserInterface` to keep the WSSE secret separate from the login password:

```php
use Escape\WSSEAuthenticationBundle\Security\Core\User\WSSEUserInterface;

class ApiUser implements UserInterface, WSSEUserInterface
{
    public function getWSSESecret(): string
    {
        return $this->apiSecret;
    }

    public function getWSSESalt(): string
    {
        return $this->apiSalt;
    }
}
```

## Usernames containing quotes

The `X-WSSE` header delimits values with double quotes, so a username containing
one cannot be transmitted as-is. Send it URL-encoded and add a marker header:

```
X-WSSE: UsernameToken Username="some%40user", PasswordDigest="...", Nonce="...", Created="..."
X-WSSE-Username-Encoded: 1
```

The username is then `urldecode()`d before the user is looked up. The marker
header is checked for presence only — any value, including `0`, enables decoding.

## Multiple firewalls and providers

Each firewall gets its own authenticator and hasher:

```yaml
security:
    providers:
        provider_one: ~
        provider_two: ~

    firewalls:
        api_one:
            provider: provider_one
            wsse: ~

        api_two:
            provider: provider_two
            wsse: ~
```

To use a provider other than the firewall's for WSSE only, set `provider` inside
the `wsse` block.

## Tests

```sh
composer install
vendor/bin/phpunit
```

With coverage (needs Xdebug or PCOV; the HTML report lands in `build/coverage`):

```sh
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text
```

## License

MIT, see [Resources/meta/LICENSE](Resources/meta/LICENSE).
