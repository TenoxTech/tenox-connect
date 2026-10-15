<?php

namespace Tenox\Connect\Tests;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tenox\Connect\Contracts\HandlesTenoxLogin;
use Tenox\Connect\TenoxIdentity;

class FakeLoginHandler implements HandlesTenoxLogin
{
    public static ?TenoxIdentity $identity = null;

    public function login(TenoxIdentity $identity, Request $request): Response
    {
        self::$identity = $identity;

        return response('logged-in:'.$request->attributes->get('tenox_return'));
    }

    public function failed(string $reason, Request $request): Response
    {
        return response('failed:'.$reason, 400);
    }
}
