<?php

use Illuminate\Support\Facades\Http;
use Tenox\Connect\Tests\FakeLoginHandler;
use Tenox\Connect\TenoxClient;

function startLogin($test, string $query = ''): array
{
    $location = $test->get('/tenox/redirect'.$query)->assertRedirect()->headers->get('Location');
    parse_str(parse_url($location, PHP_URL_QUERY), $params);
    $test->pendingNonce = session('tenox.sso.nonce');

    return [$location, $params, session('tenox.sso')];
}

it('redirects to tenox with pkce, state and nonce', function () {
    $this->fakeTenox();

    [$location, $params, $pending] = startLogin($this);

    expect($location)->toStartWith('https://id.tenox.test/oauth/authorize?');
    expect($params)->toMatchArray([
        'client_id' => 'client-123',
        'response_type' => 'code',
        'code_challenge_method' => 'S256',
        'scope' => 'openid profile email phone companies',
        'state' => $pending['state'],
        'nonce' => $pending['nonce'],
        'code_challenge' => TenoxClient::challenge($pending['verifier']),
        'redirect_uri' => 'http://localhost/tenox/callback',
    ]);
});

it('completes login and hands a verified identity to the app', function () {
    $this->fakeTenox([
        'name' => 'Бат',
        'email' => 'Bat@Example.mn',
        'email_verified' => true,
        'phone_number' => '+97699112233',
        'phone_number_verified' => true,
        'companies' => [['id' => 'c1', 'reg_no' => '1234567', 'name' => 'А ХХК', 'role' => 'owner']],
    ]);
    [, $params, $pending] = startLogin($this, '?return=/admin/surveys');

    $this->get('/tenox/callback?code=abc&state='.$params['state'])->assertOk()->assertSee('logged-in:/admin/surveys');

    $identity = FakeLoginHandler::$identity;
    expect($identity->id)->toBe('user-ulid-1');
    expect($identity->verifiedEmail())->toBe('bat@example.mn');
    expect($identity->verifiedPhone())->toBe('+97699112233');
    expect($identity->company('c1')['role'])->toBe('owner');

    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/oauth/token')
        && $request['code_verifier'] === $pending['verifier']
        && $request['client_secret'] === 'secret-xyz');
});

it('rejects a mismatched state', function () {
    $this->fakeTenox();
    startLogin($this);

    $this->get('/tenox/callback?code=abc&state=wrong')->assertStatus(400)->assertSee('failed:state');
    expect(FakeLoginHandler::$identity)->toBeNull();
});

it('rejects a callback without a pending login', function () {
    $this->get('/tenox/callback?code=abc&state=x')->assertSee('failed:state');
});

it('reports user cancellation', function () {
    $this->fakeTenox();
    startLogin($this);

    $this->get('/tenox/callback?error=access_denied')->assertSee('failed:denied');
});

it('rejects a wrong nonce', function () {
    $this->fakeTenox(['nonce' => 'other']);
    [, $params] = startLogin($this);

    $this->get('/tenox/callback?code=abc&state='.$params['state'])->assertSee('failed:token');
});

it('rejects a token for another audience', function () {
    $this->fakeTenox(['aud' => 'someone-else']);
    [, $params] = startLogin($this);

    $this->get('/tenox/callback?code=abc&state='.$params['state'])->assertSee('failed:token');
});

it('rejects a token signed by another key', function () {
    $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($other, $otherKey);
    $this->fakeTenox([], ['id_token' => $this->idToken(['nonce' => 'n'], $otherKey)]);
    [, $params] = startLogin($this);

    $this->get('/tenox/callback?code=abc&state='.$params['state'])->assertSee('failed:token');
});

it('rejects an issuer mismatch in discovery', function () {
    Http::fake(['*/.well-known/openid-configuration' => Http::response(['issuer' => 'https://evil.test'])]);

    $this->get('/tenox/redirect')->assertServerError();
});

it('ignores unsafe return paths', function () {
    $this->fakeTenox();

    foreach (['//evil.test', 'https://evil.test', '/\\evil.test'] as $return) {
        startLogin($this, '?return='.urlencode($return));
        expect(session('tenox.sso.return'))->toBeNull();
    }
});

it('calls the m2m api with a cached client token', function () {
    $this->fakeTenox();
    Http::fake([
        'https://id.tenox.test/api/m2m/*' => Http::response(['data' => ['id' => 'c1', 'reg_no' => '1234567']]),
    ]);

    $client = app(TenoxClient::class);
    expect($client->companyByRegNo('1234567')['id'])->toBe('c1');
    $client->company('c1');

    Http::assertSentCount(4);
    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer m2m-token') && str_contains($request->url(), 'reg_no=1234567'));
});

it('sends the browser to the tenox end-session endpoint', function () {
    config(['tenox.post_logout_redirect' => 'https://app.test/login']);
    $this->fakeTenox();

    $location = $this->get('/tenox/logout')->assertRedirect()->headers->get('Location');
    parse_str(parse_url($location, PHP_URL_QUERY), $query);

    expect($location)->toStartWith('https://id.tenox.test/oauth/logout?');
    expect($query)->toBe(['client_id' => 'client-123', 'post_logout_redirect_uri' => 'https://app.test/login']);
});

it('refreshes a rejected cached client token once', function () {
    $this->fakeTenox();
    cache()->put('tenox:client-token:core:read', 'stale-token', 3600);
    Http::fake([
        'https://id.tenox.test/api/m2m/*' => function ($request) {
            return $request->hasHeader('Authorization', 'Bearer stale-token')
                ? Http::response(['message' => 'Unauthenticated.'], 401)
                : Http::response(['data' => ['id' => 'c1']]);
        },
    ]);

    expect(app(TenoxClient::class)->company('c1')['id'])->toBe('c1');
    expect(cache('tenox:client-token:core:read'))->toBe('m2m-token');
});

it('caches switcher apps and hides the current app', function () {
    config(['tenox.app_key' => 'sudly']);
    $this->fakeTenox();
    Http::fake([
        'https://id.tenox.test/api/m2m/companies/c1/apps' => Http::response(['data' => [
            ['key' => 'sudly', 'name' => 'Sudly', 'enabled' => true],
            ['key' => 'ajly', 'name' => 'Ajly', 'enabled' => false],
        ]]),
    ]);

    $client = app(TenoxClient::class);
    expect(array_column($client->switcherApps('c1'), 'key'))->toBe(['ajly']);
    $client->switcherApps('c1');

    Http::assertSentCount(3);
});
