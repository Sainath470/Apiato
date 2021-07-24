<?php

namespace App\Containers\UserSection\UserContainer\Tasks;

use App\Containers\UserSection\UserContainer\Data\Repositories\UserContainerRepository;
use App\Ship\Exceptions\CreateResourceFailedException;
use App\Ship\Parents\Tasks\Task;
use Exception;

class CreateUserContainerTask extends Task
{
    protected UserContainerRepository $repository;

    public function __construct(UserContainerRepository $repository)
    {
        $this->repository = $repository;
    }

    public function run(array $data)
    {
        try {
            return $this->repository->create($data);
        }
        catch (Exception $exception) {
            throw new CreateResourceFailedException();
        }
    }
}
