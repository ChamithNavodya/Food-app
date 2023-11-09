<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
        ]);
    }

    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    // public function register(Request $request) {
    //     $validator = Validator::make($request->all(), [
    //         'name' => 'required|string|max:255',
    //         'email' => 'required|string|email|max:255|unique:users',
    //         'password' => 'required|string|min:6',
    //     ]);

    //     if ($validator->fails()) {
    //         return response()->json(['error' => $validator->errors()], 422);
    //     }

    //     $user = User::create([
    //         'name' => $request->name,
    //         'email' => $request->email,
    //         'password' => bcrypt($request->password),
    //     ]);

    //     $token = Auth::login($user);

    //     return response()->json([
    //         'status' => 'success',
    //         'message' => 'User created successfully',
    //         'user' => $user,
    //         'authorisation' => [
    //             'token' => $token,
    //             'type' => 'bearer',
    //         ]
    //     ]);

    // }


    public function register(Request $request)
    {
        $input = $request->only('name', 'email', 'password', 'c_password');

        $validator = Validator::make($input, [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:8',
            'c_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $input['password'] = bcrypt($input['password']); // use bcrypt to hash the passwords
        $user = User::create($input); // eloquent creation of data

        $success['user'] = $user;

        return response()->json([$success, 'user registered successfully'], 201);

        // return $this->sendResponse($success, 'user registered successfully', 201);
    }

    public function getUser()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return $this->sendError([], "user not found", 403);
            }
        } catch (JWTException $e) {
            return $this->sendError([], $e->getMessage(), 500);
        }

        return $this->sendResponse($user, "user data retrieved", 200);
    }
}
