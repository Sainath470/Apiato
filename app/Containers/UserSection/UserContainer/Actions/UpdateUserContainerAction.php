<?php

namespace App\Containers\UserSection\UserContainer\Actions;

use App\Containers\UserSection\UserContainer\Models\UserContainer;
use App\Containers\UserSection\UserContainer\Tasks\UpdateUserContainerTask;
use App\Ship\Parents\Actions\Action;
use App\Ship\Parents\Requests\Request;

class UpdateUserContainerAction extends Action
{
    public function run(Request $request): UserContainer
    {
        $data = $request->sanitizeInput([
            // add your request data here
        ]);

        return app(UpdateUserContainerTask::class)->run($request->id, $data);
    }
}
