<?php

/**
 * @apiGroup           UserContainer
 * @apiName            updateUserContainer
 *
 * @api                {PATCH} /v1/usercontainers/:id Endpoint title here..
 * @apiDescription     Endpoint description here..
 *
 * @apiVersion         1.0.0
 * @apiPermission      none
 *
 * @apiParam           {String}  parameters here..
 *
 * @apiSuccessExample  {json}  Success-Response:
 * HTTP/1.1 200 OK
{
  // Insert the response of the request here...
}
 */

use App\Containers\UserSection\UserContainer\UI\API\Controllers\Controller;
use Illuminate\Support\Facades\Route;

Route::patch('usercontainers/{id}', [Controller::class, 'updateUserContainer'])
    ->name('api_usercontainer_update_user_container')
    ->middleware(['auth:api']);

