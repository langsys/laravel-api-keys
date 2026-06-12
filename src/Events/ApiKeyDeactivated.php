<?php

namespace Langsys\ApiKeys\Events;

use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyDeactivated
{
    public function __construct(public ApiKey $apiKey)
    {
    }
}
