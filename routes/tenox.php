<?php

use Illuminate\Support\Facades\Route;
use Tenox\Connect\Http\Controllers\SsoController;
use Tenox\Connect\Http\Controllers\WebhookController;

Route::prefix(config('tenox.routes.prefix'))->group(function () {
    Route::middleware(config('tenox.routes.middleware'))->group(function () {
        Route::get('/redirect', [SsoController::class, 'redirect'])->middleware('throttle:30,1')->name('tenox.redirect');
        Route::get('/callback', [SsoController::class, 'callback'])->middleware('throttle:30,1')->name('tenox.callback');
        Route::get('/logout', [SsoController::class, 'logout'])->middleware('throttle:30,1')->name('tenox.logout');
    });

    Route::post('/webhook', WebhookController::class)->middleware([...config('tenox.routes.webhook_middleware'), 'throttle:300,1'])->name('tenox.webhook');
});
