<?php

namespace Langsys\ApiKeys\Events;

use Langsys\ApiKeys\Models\ApiKey;

class ApiKeyActivated
{
    public function __construct(public ApiKey $apiKey)
    {
    }
}
