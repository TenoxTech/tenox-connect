<?php

namespace Tenox\Connect\Tests;

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as Orchestra;
use Tenox\Connect\TenoxServiceProvider;

abstract class TestCase extends Orchestra
{
    protected const ISSUER = 'https://id.tenox.test';

    protected static string $privateKey;

    protected static array $jwk;

    public ?string $pendingNonce = null;

    protected function getPackageProviders($app): array
    {
        return [TenoxServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('tenox.url', self::ISSUER);
        $app['config']->set('tenox.issuer', self::ISSUER);
        $app['config']->set('tenox.client_id', 'client-123');
        $app['config']->set('tenox.client_secret', 'secret-xyz');
        $app['config']->set('tenox.webhook_secret', 'hook-secret');
        $app['config']->set('tenox.login_handler', FakeLoginHandler::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (! isset(self::$privateKey)) {
            $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($resource, $pem);
            self::$privateKey = $pem;
            $details = openssl_pkey_get_details($resource);
            self::$jwk = [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => 'test-key',
                'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
                'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
            ];
        }

        FakeLoginHandler::$identity = null;
    }

    protected function fakeTenox(array $claims = [], array $tokenOverrides = []): void
    {
        Http::fake([
            self::ISSUER.'/.well-known/openid-configuration' => Http::response([
                'issuer' => self::ISSUER,
                'authorization_endpoint' => self::ISSUER.'/oauth/authorize',
                'token_endpoint' => self::ISSUER.'/oauth/token',
                'jwks_uri' => self::ISSUER.'/oauth/jwks',
            ]),
            self::ISSUER.'/oauth/jwks' => Http::response(['keys' => [self::$jwk]]),
            self::ISSUER.'/oauth/token' => function ($request) use ($claims, $tokenOverrides) {
                if ($request['grant_type'] === 'client_credentials') {
                    return Http::response(['access_token' => 'm2m-token', 'expires_in' => 3600]);
                }

                return Http::response([
                    'access_token' => 'access-token',
                    'refresh_token' => 'refresh-token',
                    'id_token' => $this->idToken(['nonce' => $this->pendingNonce, ...$claims]),
                    ...$tokenOverrides,
                ]);
            },
        ]);
    }

    protected function idToken(array $claims = [], ?string $key = null, string $kid = 'test-key'): string
    {
        return JWT::encode([
            'iss' => self::ISSUER,
            'aud' => 'client-123',
            'sub' => 'user-ulid-1',
            'iat' => time(),
            'exp' => time() + 3600,
            ...$claims,
        ], $key ?? self::$privateKey, 'RS256', $kid);
    }
}
