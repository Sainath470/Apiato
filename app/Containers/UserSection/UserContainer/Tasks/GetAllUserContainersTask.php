<?php

namespace App\Containers\UserSection\UserContainer\Tasks;

use App\Containers\UserSection\UserContainer\Data\Repositories\UserContainerRepository;
use App\Ship\Parents\Tasks\Task;

class GetAllUserContainersTask extends Task
{
    protected UserContainerRepository $repository;

    public function __construct(UserContainerRepository $repository)
    {
        $this->repository = $repository;
    }

    public function run()
    {
        return $this->repository->paginate();
    }
}
