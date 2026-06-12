<?php

namespace Langsys\ApiKeys\Events;

use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyCreated
{
    public function __construct(public ApiKey $apiKey)
    {
    }
}
