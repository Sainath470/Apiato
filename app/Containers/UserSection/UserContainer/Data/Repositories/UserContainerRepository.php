<?php

namespace App\Containers\UserSection\UserContainer\Data\Repositories;

use App\Ship\Parents\Repositories\Repository;

class UserContainerRepository extends Repository
{
    /**
     * @var array
     */
    protected $fieldSearchable = [
        'id' => '=',
        // ...
    ];
}
