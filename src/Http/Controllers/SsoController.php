<?php

namespace Tenox\Connect\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Symfony\Component\HttpFoundation\Response;
use Tenox\Connect\Contracts\HandlesTenoxLogin;
use Tenox\Connect\TenoxClient;
use Tenox\Connect\TenoxException;

class SsoController extends Controller
{
    public function __construct(private TenoxClient $tenox, private HandlesTenoxLogin $handler) {}

    public function redirect(Request $request): RedirectResponse
    {
        $authorization = $this->tenox->authorizationRequest($this->redirectUri(), array_filter([
            'prompt' => in_array($request->query('prompt'), ['login', 'consent'], true) ? $request->query('prompt') : null,
        ]));

        $request->session()->put('tenox.sso', [
            'state' => $authorization['state'],
            'nonce' => $authorization['nonce'],
            'verifier' => $authorization['verifier'],
            'return' => $this->safeReturn($request->query('return')),
        ]);

        return redirect()->away($authorization['url']);
    }

    public function callback(Request $request): Response
    {
        $pending = $request->session()->pull('tenox.sso');

        if ($request->filled('error')) {
            return $this->handler->failed($request->query('error') === 'access_denied' ? 'denied' : 'error', $request);
        }

        if (! $pending || ! hash_equals($pending['state'], (string) $request->query('state')) || ! $request->filled('code')) {
            return $this->handler->failed('state', $request);
        }

        try {
            $identity = $this->tenox->exchangeCode($request->query('code'), $pending['verifier'], $this->redirectUri(), $pending['nonce']);
        } catch (TenoxException $e) {
            report($e);

            return $this->handler->failed('token', $request);
        }

        $request->attributes->set('tenox_return', $pending['return']);

        return $this->handler->login($identity, $request);
    }

    private function redirectUri(): string
    {
        return config('tenox.redirect') ?: route('tenox.callback');
    }

    private function safeReturn(mixed $value): ?string
    {
        return is_string($value) && preg_match('#^/(?![/\\\\])[^\s]*$#', $value) ? $value : null;
    }
}
