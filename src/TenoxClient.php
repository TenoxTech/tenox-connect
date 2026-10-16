<?php

namespace Tenox\Connect;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Support\Str;

class TenoxClient
{
    public function __construct(
        private Http $http,
        private Cache $cache,
        private array $config,
    ) {}

    public function discovery(): array
    {
        return $this->cache->remember('tenox:discovery', 3600, function () {
            $document = $this->http->timeout(10)->get($this->config['url'].'/.well-known/openid-configuration')->throw()->json();

            if (rtrim($document['issuer'] ?? '', '/') !== $this->config['issuer']) {
                throw new TenoxException('Tenox issuer таарахгүй байна: '.($document['issuer'] ?? 'null'));
            }

            return $document;
        });
    }

    /**
     * @return array{url: string, state: string, nonce: string, verifier: string}
     */
    public function authorizationRequest(string $redirectUri, array $extra = []): array
    {
        $state = Str::random(40);
        $nonce = Str::random(40);
        $verifier = Str::random(64);

        $query = http_build_query([
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->config['scopes']),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::challenge($verifier),
            'code_challenge_method' => 'S256',
            ...$extra,
        ]);

        return [
            'url' => $this->discovery()['authorization_endpoint'].'?'.$query,
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
        ];
    }

    public function logoutUrl(string $postLogoutRedirect): string
    {
        $endpoint = $this->discovery()['end_session_endpoint'] ?? $this->config['url'].'/oauth/logout';

        return $endpoint.'?'.http_build_query([
            'client_id' => $this->config['client_id'],
            'post_logout_redirect_uri' => $postLogoutRedirect,
        ]);
    }

    public function exchangeCode(string $code, string $verifier, string $redirectUri, string $nonce): TenoxIdentity
    {
        $tokens = $this->http->asForm()->timeout(10)->post($this->discovery()['token_endpoint'], [
            'grant_type' => 'authorization_code',
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret'],
            'redirect_uri' => $redirectUri,
            'code' => $code,
            'code_verifier' => $verifier,
        ]);

        if ($tokens->failed() || ! $tokens->json('id_token')) {
            throw new TenoxException('Tenox token солилт амжилтгүй: '.$tokens->json('error', $tokens->status()));
        }

        $claims = $this->verifyIdToken($tokens->json('id_token'), $nonce);

        return TenoxIdentity::fromClaims($claims, $tokens->json('access_token'), $tokens->json('refresh_token'));
    }

    public function verifyIdToken(string $idToken, ?string $nonce = null): array
    {
        $claims = $this->decode($idToken);

        if (rtrim($claims['iss'] ?? '', '/') !== $this->config['issuer']) {
            throw new TenoxException('id_token issuer буруу.');
        }

        $audience = (array) ($claims['aud'] ?? []);
        if (! in_array($this->config['client_id'], $audience, true)) {
            throw new TenoxException('id_token энэ client-д зориулагдаагүй.');
        }

        if ($nonce !== null && ! hash_equals($nonce, (string) ($claims['nonce'] ?? ''))) {
            throw new TenoxException('id_token nonce таарахгүй.');
        }

        if (empty($claims['sub'])) {
            throw new TenoxException('id_token sub байхгүй.');
        }

        return $claims;
    }

    public function clientToken(array $scopes = ['core:read']): string
    {
        $key = 'tenox:client-token:'.implode(',', $scopes);

        if ($token = $this->cache->get($key)) {
            return $token;
        }

        $response = $this->http->asForm()->timeout(10)->post($this->discovery()['token_endpoint'], [
            'grant_type' => 'client_credentials',
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret'],
            'scope' => implode(' ', $scopes),
        ])->throw();

        $token = $response->json('access_token');
        $this->cache->put($key, $token, max(60, (int) $response->json('expires_in', 3600) - 60));

        return $token;
    }

    public function api(string $path, array $query = []): array
    {
        $request = fn () => $this->http->withToken($this->clientToken())
            ->acceptJson()
            ->timeout(10)
            ->get($this->config['url'].'/api/m2m/'.ltrim($path, '/'), $query);

        $response = $request();

        if ($response->status() === 401) {
            $this->forgetClientToken();
            $response = $request();
        }

        return $response->throw()->json('data');
    }

    public function forgetClientToken(array $scopes = ['core:read']): void
    {
        $this->cache->forget('tenox:client-token:'.implode(',', $scopes));
    }

    public function userAccess(string $tenoxUserId, ?string $appKey = null): array
    {
        return $this->api('users/'.rawurlencode($tenoxUserId).'/access', ['app' => $appKey ?? $this->config['app_key']]);
    }

    public function authConfig(): array
    {
        return $this->cache->remember('tenox:auth-config', 300, fn () => $this->authCall('get', 'auth/config'));
    }

    public function forgetAuthConfig(): void
    {
        $this->cache->forget('tenox:auth-config');
    }

    /**
     * @return array{user: array, access: array}
     */
    public function passwordLogin(string $identifier, string $password): array
    {
        return $this->authCall('post', 'auth/login', ['identifier' => $identifier, 'password' => $password]);
    }

    public function sendOtp(string $phone): void
    {
        $this->authCall('post', 'auth/otp/send', ['phone' => $phone]);
    }

    /**
     * @return array{user: array, access: array}
     */
    public function verifyOtp(string $phone, string $code): array
    {
        return $this->authCall('post', 'auth/otp/verify', ['phone' => $phone, 'code' => $code]);
    }

    public function forgotPassword(string $identifier): void
    {
        $this->authCall('post', 'auth/password/forgot', ['identifier' => $identifier]);
    }

    /**
     * @return array{user: array, access: array}
     */
    public function resetPassword(string $identifier, string $code, string $password): array
    {
        return $this->authCall('post', 'auth/password/reset', ['identifier' => $identifier, 'code' => $code, 'password' => $password]);
    }

    /**
     * @param  array{name: string, phone?: ?string, email?: ?string, password: string}  $data
     * @return array{user: array, access: array}
     */
    public function register(array $data): array
    {
        return $this->authCall('post', 'auth/register', $data);
    }

    /**
     * @param  array{reg_no: string, name: string, phone?: ?string, email?: ?string}  $company
     * @return array{user: array, access: array}
     */
    public function registerCompany(string $ownerTenoxUserId, array $company): array
    {
        return $this->authCall('post', 'auth/companies', ['owner_id' => $ownerTenoxUserId, ...$company]);
    }

    /**
     * @param  array{name?: ?string, phone?: ?string, email?: ?string, current_password?: ?string, password?: ?string}  $data
     * @return array{user: array, access: array}
     */
    public function updateUser(string $tenoxUserId, array $data): array
    {
        return $this->authCall('patch', 'auth/users/'.rawurlencode($tenoxUserId), $data);
    }

    /**
     * @return array{user: array{id: string, name: ?string, phone: ?string, phone_verified: bool, email: ?string, email_verified: bool}, access: ?array}
     */
    public function getUser(string $tenoxUserId): array
    {
        return $this->authCall('get', 'auth/users/'.rawurlencode($tenoxUserId));
    }

    /**
     * @param  'phone'|'email'  $type
     */
    public function sendContactCode(string $tenoxUserId, string $type, string $value): string
    {
        return $this->authCall('post', 'auth/users/'.rawurlencode($tenoxUserId).'/contact/send', ['type' => $type, 'value' => $value])['value'];
    }

    /**
     * @param  'phone'|'email'  $type
     * @return array{user: array, access: array}
     */
    public function verifyContact(string $tenoxUserId, string $type, string $value, string $code): array
    {
        return $this->authCall('post', 'auth/users/'.rawurlencode($tenoxUserId).'/contact/verify', ['type' => $type, 'value' => $value, 'code' => $code]);
    }

    /**
     * @param  list<array{ref: int|string, name?: ?string, phone?: ?string, email?: ?string, password_hash?: ?string, phone_verified?: bool, email_verified?: bool}>  $users
     * @return list<array{ref: int|string, status: string, id?: string, reason?: string}>
     */
    public function importUsers(array $users): array
    {
        return $this->authCall('post', 'users/import', ['users' => $users], 'core:write');
    }

    public function company(string $tenoxCompanyId): array
    {
        return $this->api('companies/'.rawurlencode($tenoxCompanyId));
    }

    public function companyByRegNo(string $regNo): array
    {
        return $this->api('companies', ['reg_no' => $regNo]);
    }

    public function companyApps(string $tenoxCompanyId): array
    {
        return $this->cache->remember(
            self::appsCacheKey($tenoxCompanyId),
            $this->config['apps_cache_ttl'] ?? 300,
            fn () => $this->api('companies/'.rawurlencode($tenoxCompanyId).'/apps'),
        );
    }

    /**
     * @return list<array{key: string, name: string, description: ?string, icon: ?string, url: string, enabled: bool, links: list<array{label: string, url: string}>, enable_url: string}>
     */
    public function switcherApps(string $tenoxCompanyId): array
    {
        $current = $this->config['app_key'] ?? null;

        return array_values(array_filter(
            $this->companyApps($tenoxCompanyId),
            fn (array $app) => $app['key'] !== $current,
        ));
    }

    public function forgetCompanyApps(string $tenoxCompanyId): void
    {
        $this->cache->forget(self::appsCacheKey($tenoxCompanyId));
    }

    private static function appsCacheKey(string $tenoxCompanyId): string
    {
        return 'tenox:apps:'.$tenoxCompanyId;
    }

    private function authCall(string $method, string $path, array $data = [], string $scope = 'core:auth'): array
    {
        $request = fn () => $this->http->withToken($this->clientToken([$scope]))
            ->acceptJson()
            ->timeout(15)
            ->{$method}($this->config['url'].'/api/m2m/'.$path, $data);

        $response = $request();

        if ($response->status() === 401) {
            $this->forgetClientToken([$scope]);
            $response = $request();
        }

        if ($response->successful()) {
            return $response->json('data') ?? [];
        }

        $errors = (array) $response->json('errors', []);
        $message = collect($errors)->flatten()->first() ?? $response->json('message') ?? 'Tenox ID-тай холбогдож чадсангүй.';

        throw new TenoxAuthException($message, $response->status(), $errors);
    }

    public static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function toArray(object $claims): array
    {
        return json_decode(json_encode($claims, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
    }

    private function decode(string $jwt): array
    {
        try {
            return self::toArray(JWT::decode($jwt, $this->keys(refresh: false)));
        } catch (\UnexpectedValueException $e) {
            if (! str_contains($e->getMessage(), 'kid')) {
                throw new TenoxException('id_token баталгаажсангүй: '.$e->getMessage(), previous: $e);
            }
        }

        try {
            return self::toArray(JWT::decode($jwt, $this->keys(refresh: true)));
        } catch (\Throwable $e) {
            throw new TenoxException('id_token баталгаажсангүй: '.$e->getMessage(), previous: $e);
        }
    }

    private function keys(bool $refresh): array|\Firebase\JWT\Key
    {
        if ($refresh) {
            $this->cache->forget('tenox:jwks');
        }

        $jwks = $this->cache->remember('tenox:jwks', 43200, fn () => $this->http->timeout(10)->get($this->discovery()['jwks_uri'])->throw()->json());

        $keys = JWK::parseKeySet($jwks, 'RS256');

        return count($keys) === 1 && ! $this->hasKids($jwks) ? reset($keys) : $keys;
    }

    private function hasKids(array $jwks): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (isset($key['kid'])) {
                return true;
            }
        }

        return false;
    }
}
