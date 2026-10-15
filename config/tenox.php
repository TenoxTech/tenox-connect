<?php

return [
    'url' => rtrim(env('TENOX_URL', 'https://id.tenox.mn'), '/'),

    'issuer' => rtrim(env('TENOX_ISSUER', env('TENOX_URL', 'https://id.tenox.mn')), '/'),

    'app_key' => env('TENOX_APP_KEY'),

    'client_id' => env('TENOX_CLIENT_ID'),

    'client_secret' => env('TENOX_CLIENT_SECRET'),

    'redirect' => env('TENOX_REDIRECT_URI'),

    'post_logout_redirect' => env('TENOX_POST_LOGOUT_REDIRECT_URI'),

    'scopes' => ['openid', 'profile', 'email', 'phone', 'companies'],

    'webhook_secret' => env('TENOX_WEBHOOK_SECRET'),

    'webhook_tolerance' => 300,

    'apps_cache_ttl' => 300,

    'login_handler' => null,

    'routes' => [
        'enabled' => true,
        'prefix' => 'tenox',
        'middleware' => ['web'],
        'webhook_middleware' => ['api'],
    ],
];
