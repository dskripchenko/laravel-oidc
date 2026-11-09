# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-11-09

First release.

### Added
- `OidcClient`: discovery (kept an hour, taken only for the configured
  issuer), the authorization URL with PKCE S256, state and nonce, the code
  exchange (`tokens()`) and the userinfo (`userInfo()`: `UserInfo`,
  `verifiedEmail()` only for `email_verified: true`).
- `SignIn\SignInFlow`: `start()` keeps the state, PKCE verifier and nonce in
  the session; `finish()` checks the state once, trades the code, requires
  and validates the ID token (`SignIn\IdTokens`), then reads the userinfo,
  which must name the same `sub` (`SignInResult` with the userinfo, the
  context given at the start and the ID token's claims).
- ID token validation: RS256 or ES256 by a key of the issuer's JWKS (never
  `none`), `iss`, `aud` holding the client ID (and `azp` the client ID with
  several audiences or any `azp`), `exp` and `iat` within
  `oidc.id_token_leeway` (`OIDC_ID_TOKEN_LEEWAY`, 60 s by default), `sub`,
  and the session's nonce. Failures: `ProviderError` with
  `id_token_missing`, `id_token_invalid`, `nonce_mismatch`, `sub_mismatch`.
- `IssuerKeys`: the issuer's JWKS for ID tokens and access tokens alike.
- `Jose\Jwt`, `Jose\Jwk`: JWS compact tokens checked with OpenSSL —
  RS256/384/512, ES256/384/512 on their own curves, RSA keys from 2048 bits;
  never `none` or HMAC.
- `Tokens\ProviderTokens`: provider access tokens for an API — type,
  signature by `kid`, issuer, audience (not the sign-in client unless
  allowed), client allow-list, `exp`/`nbf` with 60 s leeway, subject, groups
  and their freshness. JWKS kept an hour, refetched at most once a minute for
  an unknown key, a failed fetch remembered 30 s.
- `Http\Middleware\AuthenticateProviderToken`: signs a request in as the
  token's person on `oidc.api_guard`, keeps `ProviderAccessToken` in the
  request; 429 after 30 rejections a minute per address, `ProviderTokenRejected`
  for the first 5.
- `Groups\GroupClaims`, `Groups\RoleMapping`: the groups claim, the blocked
  group, `group=role` pairs and the give / take over / take back decision.
- Contracts `SubjectUsers`, `GroupSync`, `OutboundHttp` with defaults
  `EloquentSubjectUsers`, `NullGroupSync`, `PlainOutboundHttp`.
- Exceptions `ProviderError`, `StateMismatch`, `TokenRejected` (401),
  `TooManyAttempts` (429), all `OidcException` with `reason()`.
