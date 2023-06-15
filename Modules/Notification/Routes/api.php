<?php

use Illuminate\Support\Facades\Route;
use Modules\Notification\Http\Controllers\NotificationController;

Route::group(['middleware' => 'auth:api'], function () {
    Route::post('notifications/{id}/mark-as-read', [NotificationController::class, 'markAsRead']);
});
