<?php

namespace App\Containers\UserSection\UserContainer\UI\API\Controllers;

use App\Containers\UserSection\UserContainer\Models\UserContainer;
use App\Ship\Parents\Controllers\ApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class UserController extends ApiController
{
    public function register(Request $request)
    {
        $req = Validator::make($request->all(), [
            'firstName' => 'required|string|between:2,100',
            'lastName' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:user_containers'
        ]);

        $req2 = Validator::make($request->all(), [
            'password' => 'required|required_with:password_confirmation|min:3',
            'password_confirmation' => 'required|same:password'
        ]);

        $user = new UserContainer();
        $user->firstName = $request->input('firstName');
        $user->lastName = $request->input('lastName');
        $user->email = $request->input('email');
        $user->password = bcrypt($request->input('password'));

        $userEmail = UserContainer::where('email', $user->email)->first();
        if ($userEmail) {
            return response()->json(['status' => 409, 'message' => "This email already exists...."]);
        }

        if ($req->fails()) {
            return response()->json(['status' => 403, 'message' => "Please enter the valid details"]);
        }

        if ($req2->fails()) {
            return response()->json(['status' => 403, 'message' => "Password doesn't match"]);
        }
        $user->save();
        return response()->json([
            'status' => 201,
            'message' => 'User succesfully registered!'
        ]);
    }

    public function login(Request $request)
    {
        $req = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|
            min:5',
        ]);

        $email = $request->get('email');
        $user = UserContainer::where('email', $email)
            ->first();

        if (!$user) {
            return response()->json(['status' => 400, 'message' => "Invalid credentials! email doesn't exists"]);
        }

        if ($req->fails()) {
            return response()->json(['status' => 403, 'message' => "please enter the valid details"]);
        }

        $token = JWTAuth::fromUser($user);
        if (!$token) {
            return response()->json(['status' => 401, 'message' => 'Unauthenticated']);
        }
        return $this->generateToken($token);
    }

    public function generateToken($token)
    {
        return response()->json([
            'status' => 201,
            'message' => 'succesfully logged in',
            'token' => $token
        ]);
    }
}
