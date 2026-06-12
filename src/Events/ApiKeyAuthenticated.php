<?php

namespace Langsys\ApiKeys\Events;

use Illuminate\Http\Request;
use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyAuthenticated
{
    public function __construct(
        public ApiKey $apiKey,
        public Request $request,
    ) {
    }
}
