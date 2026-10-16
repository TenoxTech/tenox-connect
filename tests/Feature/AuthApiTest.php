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

it('registers a company for an owner', function () {
    Http::fake(['https://id.tenox.test/api/m2m/auth/companies' => Http::response(['data' => ['user' => ['id' => 'u1'], 'access' => ['role' => 'company_admin', 'company' => ['id' => 'c1', 'reg_no' => '1234567', 'name' => 'А']]]], 201)]);

    expect(app(TenoxClient::class)->registerCompany('u1', ['reg_no' => '1234567', 'name' => 'А'])['access']['role'])->toBe('company_admin');
    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/auth/companies') && $request['owner_id'] === 'u1' && $request['reg_no'] === '1234567');
});

it('requests and completes a password reset', function () {
    Http::fake([
        'https://id.tenox.test/api/m2m/auth/password/forgot' => Http::response(['data' => ['sent' => true]]),
        'https://id.tenox.test/api/m2m/auth/password/reset' => Http::response(['data' => ['user' => ['id' => 'u1'], 'access' => null]]),
    ]);

    $client = app(TenoxClient::class);
    $client->forgotPassword('a@b.mn');

    expect($client->resetPassword('a@b.mn', '123456', 'newpass123')['user']['id'])->toBe('u1');
    Http::assertSent(fn ($request) => str_ends_with($request->url(), '/password/reset') && $request['code'] === '123456');
});

it('changes a contact through a verification code', function () {
    Http::fake([
        'https://id.tenox.test/api/m2m/auth/users/u1/contact/send' => Http::response(['data' => ['sent' => true, 'value' => '+97688001122']]),
        'https://id.tenox.test/api/m2m/auth/users/u1/contact/verify' => Http::response(['data' => ['user' => ['id' => 'u1', 'phone' => '+97688001122', 'phone_verified' => true], 'access' => null]]),
    ]);

    $client = app(TenoxClient::class);
    expect($client->sendContactCode('u1', 'phone', '88001122'))->toBe('+97688001122');
    expect($client->verifyContact('u1', 'phone', '88001122', '123456')['user']['phone_verified'])->toBeTrue();
});

it('reads a user with verification status', function () {
    Http::fake(['https://id.tenox.test/api/m2m/auth/users/u1' => Http::response(['data' => ['user' => ['id' => 'u1', 'phone_verified' => true], 'access' => null]])]);

    expect(app(TenoxClient::class)->getUser('u1')['user']['phone_verified'])->toBeTrue();
});
