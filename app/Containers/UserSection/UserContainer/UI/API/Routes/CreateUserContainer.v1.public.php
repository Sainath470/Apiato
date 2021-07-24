<?php

/**
 * @apiGroup           UserContainer
 * @apiName            createUserContainer
 *
 * @api                {POST} /v1/usercontainers Endpoint title here..
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

Route::post('usercontainers', [Controller::class, 'createUserContainer'])
    ->name('api_usercontainer_create_user_container')
    ->middleware(['auth:api']);

