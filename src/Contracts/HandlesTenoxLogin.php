<?php

namespace Tenox\Connect\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tenox\Connect\TenoxIdentity;

interface HandlesTenoxLogin
{
    public function login(TenoxIdentity $identity, Request $request): Response;

    public function failed(string $reason, Request $request): Response;
}
