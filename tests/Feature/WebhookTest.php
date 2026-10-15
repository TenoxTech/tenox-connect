<?php

use Illuminate\Support\Facades\Event;
use Tenox\Connect\Events\TenoxWebhookReceived;

function signedPost($test, array $payload, ?string $secret = 'hook-secret')
{
    $body = json_encode($payload);

    return $test->call('POST', '/tenox/webhook', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_TENOX_SIGNATURE' => 'sha256='.hash_hmac('sha256', $body, $secret),
    ], $body);
}

function payload(array $overrides = []): array
{
    return ['id' => 'd-1', 'event' => 'company.updated', 'data' => ['company' => ['id' => 'c1', 'name' => 'Шинэ']], 'sent_at' => now()->toIso8601String(), ...$overrides];
}

it('dispatches a verified webhook once', function () {
    Event::fake();

    signedPost($this, payload())->assertOk()->assertJson(['status' => 'ok']);
    signedPost($this, payload())->assertOk()->assertJson(['status' => 'duplicate']);

    Event::assertDispatchedTimes(TenoxWebhookReceived::class, 1);
    Event::assertDispatched(TenoxWebhookReceived::class, fn ($event) => $event->event === 'company.updated' && $event->data['company']['name'] === 'Шинэ');
});

it('rejects bad signatures', function () {
    Event::fake();

    signedPost($this, payload(), 'wrong')->assertUnauthorized();
    Event::assertNotDispatched(TenoxWebhookReceived::class);
});

it('rejects stale deliveries', function () {
    signedPost($this, payload(['sent_at' => now()->subHour()->toIso8601String()]))->assertStatus(422);
});

it('is disabled without a secret', function () {
    config(['tenox.webhook_secret' => null]);

    signedPost($this, payload())->assertNotFound();
});

it('clears the cached app list for the company', function () {
    cache()->put('tenox:apps:c1', [['key' => 'old']], 300);

    signedPost($this, payload(['id' => 'd-9', 'event' => 'app.enabled']))->assertOk();

    expect(cache()->has('tenox:apps:c1'))->toBeFalse();
});

it('drops the cached auth config when the app settings change', function () {
    cache()->put('tenox:auth-config', ['methods' => ['password']], 300);

    signedPost($this, payload(['id' => 'd-app', 'event' => 'app.updated', 'data' => ['app' => 'sudly']]))->assertOk();

    expect(cache()->has('tenox:auth-config'))->toBeFalse();
});
