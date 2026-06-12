<?php

namespace Langsys\ApiKeys\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Langsys\ApiKeys\Enums\ApiKeyType;
use Langsys\ApiKeys\Events\ApiKeyAuthenticated;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateApiKey
{
    public function handle(Request $request, Closure $next): Response
    {
        $model = config('api-keys.model');
        $key = $request->header(config('api-keys.header', 'X-Api-Key'));

        if (! $key) {
            if (config('api-keys.allow_authenticated_users', true) && $request->user()) {
                return $next($request);
            }

            return $this->deny('API key is required.', 401);
        }

        $apiKey = $model::getByKey($key);

        if (! $apiKey) {
            return $this->deny('Invalid API key.', 401);
        }

        if (! $apiKey->active) {
            return $this->deny('API key is inactive.', 403);
        }

        if (config('api-keys.enforce_read_write', true) && ! $this->methodAllowed($request, $apiKey)) {
            return $this->deny('This API key is read-only.', 403);
        }

        $requestId = (string) Str::uuid();
        $request->headers->set('X-Request-ID', $requestId);
        $request->attributes->set('api_key', $apiKey);
        app()->instance('api-keys.current', $apiKey);

        event(new ApiKeyAuthenticated($apiKey, $request));

        $response = $next($request);
        $response->headers->set('X-Request-ID', $requestId);

        return $response;
    }

    private function methodAllowed(Request $request, mixed $apiKey): bool
    {
        if (in_array($request->method(), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return true;
        }

        return $apiKey->type === ApiKeyType::WRITE;
    }

    private function deny(string $message, int $status): Response
    {
        return response()->json(['message' => $message], $status);
    }
}
