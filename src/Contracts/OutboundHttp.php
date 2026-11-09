<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Contracts;

use Illuminate\Http\Client\PendingRequest;

/**
 * Requests to an address the provider published rather than one an
 * administrator configured: the JWKS (`jwks_uri` of the discovery
 * document). Bind an implementation that guards against requests into the
 * private network (SSRF) when the application has one.
 */
interface OutboundHttp
{
    /** A request for this URL only; requests to other hosts must not be made with it. */
    public function request(string $url): PendingRequest;
}
