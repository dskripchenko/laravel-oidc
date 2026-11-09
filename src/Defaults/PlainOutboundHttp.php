<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Defaults;

use Dskripchenko\Oidc\Contracts\OutboundHttp;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;

/**
 * The HTTP client as is, with a timeout and no redirects.
 */
final readonly class PlainOutboundHttp implements OutboundHttp
{
    public function __construct(private Factory $http) {}

    public function request(string $url): PendingRequest
    {
        return $this->http->timeout(10)->withoutRedirecting();
    }
}
