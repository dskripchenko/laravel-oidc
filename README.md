# dskripchenko/laravel-oidc

OpenID Connect for Laravel, without a JOSE library:

- **Sign-in** through the authorization code flow with PKCE (S256), a state
  and a nonce kept in the session, the code traded for the person's userinfo.
- **Provider access tokens for an API**: an outside client signed in through
  the same provider calls the API with the provider's token (a JWT), checked
  against the issuer's JWKS — RS256/384/512 and ES256/384/512 only, never
  `none` or HMAC.
- **Groups** from the provider: the claim read, a "blocked" group, roles from
  `group=role` pairs, and a freshness rule for tokens without groups.

The package does not decide who the person is in your application: who a
subject is, what groups do and what a provider's token may do are yours,
through two small contracts.

PHP 8.3+, Laravel 11–13, ext-openssl.

## Install

```bash
composer require dskripchenko/laravel-oidc
php artisan vendor:publish --tag=oidc-config   # optional
```

```dotenv
OIDC_ISSUER=https://sso.example.com
OIDC_CLIENT_ID=my-app
OIDC_CLIENT_SECRET=...
OIDC_SCOPES="openid profile email groups"
```

The provider's endpoints come from `<issuer>/.well-known/openid-configuration`.
The document is kept an hour and taken only when its `issuer` is the
configured one.

## Sign-in

The routes and the session are yours; `SignInFlow` does the protocol.

```php
use Dskripchenko\Oidc\Exceptions\OidcException;
use Dskripchenko\Oidc\OidcClient;
use Dskripchenko\Oidc\SignIn\SignInFlow;

Route::get('/auth/oidc/redirect', function (Request $request, SignInFlow $flow) {
    abort_unless(OidcClient::enabled(), 404);

    return redirect()->away($flow->start($request->session(), ['back' => '/']));
});

Route::get('/auth/oidc/callback', function (Request $request, SignInFlow $flow) {
    try {
        $result = $flow->finish($request);         // state checked, code traded
    } catch (OidcException $e) {
        return redirect('/login?sso='.$e->reason()); // state, callback, token, ...
    }
    $info = $result->user;                          // Dskripchenko\Oidc\UserInfo
    $user = User::firstWhere('oidc_subject', $info->subject)
        ?? User::firstWhere('email', $info->verifiedEmail()); // null unless email_verified === true
    // ... your rules, then:
    Auth::login($user);
    $request->session()->regenerate();

    return redirect($result->context['back']);
});
```

`UserInfo` has `subject`, `email` (lower case), `emailVerified`, `name`
(`name`, else `preferred_username`), `groups` (the `OIDC_GROUPS_CLAIM` claim,
null when absent) and the raw `claims`. `verifiedEmail()` returns the email
only when the provider says `email_verified: true` — an address it does not
vouch for may be anyone's typing and must not match an account.

The callback state is taken out of the session, so a callback works once.
The ID token is not used: the userinfo endpoint is called with the access
token the provider gave this server over TLS.

## Provider access tokens in an API

```dotenv
OIDC_API_TOKENS=true
OIDC_API_AUDIENCE=my-api          # required; not OIDC_CLIENT_ID (see below)
OIDC_API_CLIENTS=chat,mobile      # required: azp / client_id of the token
OIDC_API_GUARD=sanctum            # optional; the default guard otherwise
```

```php
use Dskripchenko\Oidc\Http\Middleware\AuthenticateProviderToken;
use Dskripchenko\Oidc\Tokens\ProviderAccessToken;

Route::middleware([AuthenticateProviderToken::class, 'auth:sanctum'])->get('/api/me', function (Request $request) {
    $token = ProviderAccessToken::of($request); // null for any other credential

    return ['user' => $request->user()->id, 'client' => $token?->client];
});
```

A bearer that looks like a JWT is checked; any other bearer passes through to
your own tokens. A JWT that does not pass gets 401 (`TokenRejected`), never a
second try as something else. A token is taken when:

| Check | Rejection reason |
|---|---|
| a well-formed JWS, at most 16 KiB | `format` |
| `alg` is RS256/384/512 or ES256/384/512 | `algorithm` |
| header `typ` is in `OIDC_API_TOKEN_TYPES` (default `at+jwt`, RFC 9068), and the claims do not say ID token (`typ: ID`, `token_use: id`) | `type` |
| signed by a key of the issuer's JWKS, by `kid`; the key's `kty`, `alg`, `use` and EC curve match the algorithm | `signature` |
| `iss` is the issuer | `issuer` |
| `aud` holds `OIDC_API_AUDIENCE` | `audience` |
| `azp` (else `client_id`) is in `OIDC_API_CLIENTS` | `client` |
| `exp` not passed, `nbf` reached (60 s leeway) | `expired`, `not_yet` |
| `sub` names a person `SubjectUsers` returns | `subject` |
| groups fresh enough (below) | `groups_stale` |

`OIDC_API_AUDIENCE` equal to `OIDC_CLIENT_ID` is ignored — a token for your
own sign-in is not one for the API — unless
`OIDC_API_AUDIENCE_SAME_AS_CLIENT=true`. Providers that type access tokens
`JWT` (Keycloak) need `OIDC_API_TOKEN_TYPES=at+jwt,JWT`; the audience and the
client list still keep their ID tokens out.

**JWKS.** Fetched from the discovery document's `jwks_uri` through the
`OutboundHttp` contract and kept an hour. An unknown `kid` refetches at most
once a minute: a rotated key is picked up, a stream of made-up key IDs does
not make the server call out. A failed fetch is remembered for 30 seconds.

**Rate limit.** After 30 rejected tokens from one address in a minute the
address gets 429 (`TooManyAttempts`, `Retry-After`). The first 5 rejections
of a minute dispatch `ProviderTokenRejected` with the reason and the IP —
never the token or its claims — for your audit log.

The token grants nothing by itself: decide what a request with
`ProviderAccessToken::of($request) !== null` may do. Do not mint your own
long-lived tokens from it: they would outlive the provider's token and its
block.

## Groups

```php
use Dskripchenko\Oidc\Groups\GroupClaims;
use Dskripchenko\Oidc\Groups\RoleMapping;

GroupClaims::of($claims);          // list<string>|null from OIDC_GROUPS_CLAIM
GroupClaims::blocks($groups);      // in OIDC_BLOCKED_GROUP?

RoleMapping::pairs();              // OIDC_ROLE_GROUPS="admins=admin,auditors=auditor"
RoleMapping::decide($givingGroups, $groups, $heldFromProvider); // RoleChange|null
```

`decide()` gives a role to a member of one of its groups, takes over a role
held by hand when the person joins its group, and takes back only a role the
provider gave — never one given by hand. You store where a role came from and
apply the change.

With a groups claim in an access token, `GroupSync::sync()` runs as at a
sign-in (once a minute per person and set of groups); returning false — a
blocked person — rejects the token. A token without the claim is taken only
while `GroupSync::syncedAt()` is within `OIDC_API_SYNC_MAX_AGE` hours (24),
and only if `GroupSync::followsGroups()`.

## Contracts

| Contract | Default | Bind your own to |
|---|---|---|
| `Contracts\SubjectUsers` | `EloquentSubjectUsers`: the `users` provider's model (or `oidc.users.model`) by `oidc_issuer` and `oidc_subject` | leave out blocked accounts and service accounts |
| `Contracts\GroupSync` | `NullGroupSync`: nothing follows groups | apply teams, roles, the block |
| `Contracts\OutboundHttp` | `PlainOutboundHttp`: timeout, no redirects | guard the JWKS request against SSRF |

## Exceptions

All implement `Exceptions\OidcException` with a short `reason()`:
`ProviderError` (`discovery`, `endpoint`, `token`, `userinfo`, `callback`),
`StateMismatch` (`state`), `TokenRejected` (401, reasons above),
`TooManyAttempts` (429).

## Testing

```bash
composer test      # pest
composer analyse   # phpstan, level max
composer format    # pint
```

## License

MIT. See [LICENSE](LICENSE).
