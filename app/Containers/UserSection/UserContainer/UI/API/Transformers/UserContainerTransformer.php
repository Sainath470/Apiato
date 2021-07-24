<?php

namespace App\Containers\UserSection\UserContainer\UI\API\Transformers;

use App\Containers\UserSection\UserContainer\Models\UserContainer;
use App\Ship\Parents\Transformers\Transformer;

class UserContainerTransformer extends Transformer
{
    /**
     * @var  array
     */
    protected $defaultIncludes = [

    ];

    /**
     * @var  array
     */
    protected $availableIncludes = [

    ];

    public function transform(UserContainer $usercontainer): array
    {
        $response = [
            'object' => $usercontainer->getResourceKey(),
            'id' => $usercontainer->getHashedKey(),
            'created_at' => $usercontainer->created_at,
            'updated_at' => $usercontainer->updated_at,
            'readable_created_at' => $usercontainer->created_at->diffForHumans(),
            'readable_updated_at' => $usercontainer->updated_at->diffForHumans(),

        ];

        $response = $this->ifAdmin([
            'real_id'    => $usercontainer->id,
            // 'deleted_at' => $usercontainer->deleted_at,
        ], $response);

        return $response;
    }
}
