<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc\Tests;

use Dskripchenko\Oidc\OidcServiceProvider;
use Orchestra\Testbench\TestCase as Base;

abstract class TestCase extends Base
{
    protected function getPackageProviders($app): array
    {
        return [OidcServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
    }
}
