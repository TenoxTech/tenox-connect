<?php

use Illuminate\Support\Facades\Http;
use Tenox\Connect\TenoxAuthException;
use Tenox\Connect\TenoxClient;

beforeEach(function () {
    $this->fakeTenox();
});

it('logs in through core with a core:auth client token', function () {
    Http::fake(['https://id.tenox.test/api/m2m/auth/login' => Http::response(['data' => ['user' => ['id' => 'u1'], 'access' => ['role' => null, 'blocked' => false]]])]);

    expect(app(TenoxClient::class)->passwordLogin('99112233', 'secret')['user']['id'])->toBe('u1');

    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/oauth/token') && $request['scope'] === 'core:auth');
    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/api/m2m/auth/login') && $request['identifier'] === '99112233');
});

it('surfaces core validation messages', function () {
    Http::fake(['https://id.tenox.test/api/m2m/auth/login' => Http::response(['message' => 'x', 'errors' => ['identifier' => ['Нэвтрэх нэр эсвэл нууц үг буруу.']]], 422)]);

    try {
        app(TenoxClient::class)->passwordLogin('a@b.mn', 'bad');
        $this->fail('expected exception');
    } catch (TenoxAuthException $e) {
        expect($e->getMessage())->toBe('Нэвтрэх нэр эсвэл нууц үг буруу.');
        expect($e->status)->toBe(422);
        expect($e->errors)->toHaveKey('identifier');
    }
});

it('imports users with a core:write token', function () {
    Http::fake(['https://id.tenox.test/api/m2m/users/import' => Http::response(['data' => [['ref' => 1, 'status' => 'created', 'id' => 'u1']]])]);

    expect(app(TenoxClient::class)->importUsers([['ref' => 1, 'phone' => '99112233']])[0]['status'])->toBe('created');
    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/oauth/token') && $request['scope'] === 'core:write');
});

it('caches the auth config', function () {
    Http::fake(['https://id.tenox.test/api/m2m/auth/config' => Http::response(['data' => ['methods' => ['password'], 'registration' => true]])]);

    $client = app(TenoxClient::class);
    $client->authConfig();
    expect($client->authConfig()['methods'])->toBe(['password']);

    Http::assertSentCount(3);
});
