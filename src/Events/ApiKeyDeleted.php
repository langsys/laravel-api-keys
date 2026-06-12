<?php

namespace Langsys\ApiKeys\Events;

use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyDeleted
{
    public function __construct(public ApiKey $apiKey)
    {
    }
}
