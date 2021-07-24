<?php

namespace App\Containers\UserSection\UserContainer\Tasks;

use App\Containers\UserSection\UserContainer\Data\Repositories\UserContainerRepository;
use App\Ship\Exceptions\UpdateResourceFailedException;
use App\Ship\Parents\Tasks\Task;
use Exception;

class UpdateUserContainerTask extends Task
{
    protected UserContainerRepository $repository;

    public function __construct(UserContainerRepository $repository)
    {
        $this->repository = $repository;
    }

    public function run($id, array $data)
    {
        try {
            return $this->repository->update($data, $id);
        }
        catch (Exception $exception) {
            throw new UpdateResourceFailedException();
        }
    }
}
