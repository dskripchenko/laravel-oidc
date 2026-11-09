<?php

declare(strict_types=1);

namespace Dskripchenko\Oidc;

use Dskripchenko\Oidc\Contracts\GroupSync;
use Dskripchenko\Oidc\Contracts\OutboundHttp;
use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Dskripchenko\Oidc\Defaults\EloquentSubjectUsers;
use Dskripchenko\Oidc\Defaults\NullGroupSync;
use Dskripchenko\Oidc\Defaults\PlainOutboundHttp;
use Illuminate\Support\ServiceProvider;

final class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        // The application's own bindings win.
        $this->app->bindIf(SubjectUsers::class, EloquentSubjectUsers::class);
        $this->app->bindIf(GroupSync::class, NullGroupSync::class);
        $this->app->bindIf(OutboundHttp::class, PlainOutboundHttp::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/oidc.php' => config_path('oidc.php')], 'oidc-config');
        }
    }
}
