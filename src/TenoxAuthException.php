<?php

namespace Tenox\Connect;

class TenoxAuthException extends TenoxException
{
    /**
     * @param  array<string, list<string>>  $errors
     */
    public function __construct(string $message, public readonly int $status = 422, public readonly array $errors = [])
    {
        parent::__construct($message, $status);
    }
}
