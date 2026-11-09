# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## Reporting a vulnerability

Please report vulnerabilities privately. Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on
[github.com/dskripchenko/laravel-oidc](https://github.com/dskripchenko/laravel-oidc/security/advisories/new),
or write to denskrp90@gmail.com. Do not open a public issue for a vulnerability.
Include affected versions and, if possible, a proof of concept.

You will get an answer within five working days. A confirmed issue is fixed in a
patch release of every supported line, published as a GitHub security advisory once
the release is out, and credited in the changelog unless you ask otherwise.

## Security model in short

- Sign-in: authorization code flow with PKCE S256; the state is compared in constant
  time and, with the nonce, taken out of the session, so a callback works once. The ID
  token is required and validated (RS256/ES256 against the JWKS, `iss`, `aud`/`azp`,
  `exp`/`iat`, nonce); the userinfo must name its `sub`. The discovery document is
  taken only when its `issuer` is the configured one.
- Only an email the provider marks `email_verified: true` is offered for matching
  accounts (`UserInfo::verifiedEmail()`).
- Provider access tokens: asymmetric signatures only (RS/ES 256/384/512, EC keys on the
  algorithm's own curve, RSA from 2048 bits), never `none` or HMAC; an RFC 9068 type,
  not an ID token; issuer, a dedicated audience, an allow-list of clients, `exp`/`nbf`.
- The JWKS URL comes from the provider: bind `OutboundHttp` to a client that refuses
  private addresses if your network needs it. Unknown key IDs refetch at most once a
  minute; failures are cached 30 seconds.
- Rejections are rate-limited per address and reported without the token or claims.
