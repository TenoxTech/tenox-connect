<?php

namespace Tenox\Connect\Events;

use Illuminate\Foundation\Events\Dispatchable;

class TenoxWebhookReceived
{
    use Dispatchable;

    public function __construct(
        public readonly string $event,
        public readonly array $data,
        public readonly string $deliveryId,
    ) {}
}
