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

            // publishesMigrations() only exists on Laravel 11+; plain publishes()
            // covers Laravel 10 (illuminate/support ^10 is supported).
            $migrations = [__DIR__ . '/../database/migrations' => database_path('migrations')];

            if (method_exists($this, 'publishesMigrations')) {
                $this->publishesMigrations($migrations, 'api-keys-migrations');
            } else {
                $this->publishes($migrations, 'api-keys-migrations');
            }
        }
    }
}
