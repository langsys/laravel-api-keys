<?php

namespace Langsys\ApiKeys;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Langsys\ApiKeys\Http\Middleware\AuthenticateApiKey;

class ApiKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/api-keys.php', 'api-keys');
    }

    public function boot(): void
    {
        $this->app->make(Router::class)->aliasMiddleware('api-key', AuthenticateApiKey::class);

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/api-keys.php' => config_path('api-keys.php'),
            ], 'api-keys-config');

            $this->publishesMigrations([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'api-keys-migrations');
        }
    }
}
