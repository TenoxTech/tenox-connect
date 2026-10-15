<?php

namespace Tenox\Connect;

use Illuminate\Support\ServiceProvider;
use Tenox\Connect\Contracts\HandlesTenoxLogin;

class TenoxServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/tenox.php', 'tenox');

        $this->app->singleton(TenoxClient::class, fn ($app) => new TenoxClient(
            $app['http'] ?? $app->make(\Illuminate\Http\Client\Factory::class),
            $app['cache']->store(),
            $app['config']['tenox'],
        ));

        $this->app->bind(HandlesTenoxLogin::class, function ($app) {
            $handler = $app['config']['tenox.login_handler'];

            if (! $handler) {
                throw new TenoxException('config/tenox.php дотор login_handler тохируулаагүй байна.');
            }

            return $app->make($handler);
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/tenox.php' => config_path('tenox.php')], 'tenox-config');

        if (config('tenox.routes.enabled')) {
            $this->loadRoutesFrom(__DIR__.'/../routes/tenox.php');
        }
    }
}
