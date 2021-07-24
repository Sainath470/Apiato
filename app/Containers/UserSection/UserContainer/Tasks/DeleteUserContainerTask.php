<?php

namespace App\Containers\UserSection\UserContainer\Tasks;

use App\Containers\UserSection\UserContainer\Data\Repositories\UserContainerRepository;
use App\Ship\Exceptions\DeleteResourceFailedException;
use App\Ship\Parents\Tasks\Task;
use Exception;

class DeleteUserContainerTask extends Task
{
    protected UserContainerRepository $repository;

    public function __construct(UserContainerRepository $repository)
    {
        $this->repository = $repository;
    }

    public function run($id): ?int
    {
        try {
            return $this->repository->delete($id);
        }
        catch (Exception $exception) {
            throw new DeleteResourceFailedException();
        }
    }
}
