<?php

namespace Tenox\Connect\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Tenox\Connect\Events\TenoxWebhookReceived;
use Tenox\Connect\TenoxClient;

class WebhookController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $secret = config('tenox.webhook_secret');
        abort_unless($secret, 404);

        $body = $request->getContent();
        $expected = 'sha256='.hash_hmac('sha256', $body, $secret);
        abort_unless(hash_equals($expected, (string) $request->header('X-Tenox-Signature')), 401, 'Invalid signature');

        $payload = json_decode($body, true);
        abort_unless(is_array($payload) && isset($payload['id'], $payload['event'], $payload['sent_at']), 422);

        try {
            $sentAt = Carbon::parse($payload['sent_at']);
        } catch (\Throwable) {
            abort(422, 'Invalid sent_at');
        }
        abort_if(abs(now()->diffInSeconds($sentAt)) > config('tenox.webhook_tolerance', 300), 422, 'Stale webhook');

        $key = 'tenox:webhook:'.$payload['id'];
        if (Cache::has($key)) {
            return response()->json(['status' => 'duplicate']);
        }

        $data = $payload['data'] ?? [];
        if ($payload['event'] === 'app.updated') {
            app(TenoxClient::class)->forgetAuthConfig();
        }
        if ($companyId = $data['company']['id'] ?? $data['company_id'] ?? null) {
            app(TenoxClient::class)->forgetCompanyApps((string) $companyId);
        }

        TenoxWebhookReceived::dispatch($payload['event'], $data, $payload['id']);
        Cache::put($key, true, now()->addDay());

        return response()->json(['status' => 'ok']);
    }
}
