<?php

namespace App\Containers\UserSection\UserContainer\Tasks;

use App\Containers\UserSection\UserContainer\Data\Repositories\UserContainerRepository;
use App\Ship\Exceptions\NotFoundException;
use App\Ship\Parents\Tasks\Task;
use Exception;

class FindUserContainerByIdTask extends Task
{
    protected UserContainerRepository $repository;

    public function __construct(UserContainerRepository $repository)
    {
        $this->repository = $repository;
    }

    public function run($id)
    {
        try {
            return $this->repository->find($id);
        }
        catch (Exception $exception) {
            throw new NotFoundException();
        }
    }
}
