<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Database\QueryException;
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

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'required|email',
                'password' => 'required|string',
            ]);
            $credentials = $request->only('email', 'password');

            if (!$token = auth()->attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 401);
            }

            return $this->respondWithToken($token);
        } catch (QueryException $exception) {

            return response()->json(['error' => 'Database error: ' . $exception->getMessage()], 500);
        } catch (\Exception $exception) {

            return response()->json(['error' => 'An unexpected error occurred'], 500);
        }
    }

    public function logout()
    {
        try {
            $user = Auth::user();

            if ($user) {
                $user->tokens->each(function ($token) {
                    $token->delete();
                });
            }

            Auth::logout();

            return response()->json(['message' => 'Successfully logged out']);
        } catch (QueryException $exception) {

            return response()->json(['error' => 'Database error: ' . $exception->getMessage()], 500);
        } catch (\Exception $exception) {

            return response()->json(['error' => 'An unexpected error occurred'], 500);
        }
    }


    public function register(Request $request)
    {
        try {
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

            $input['password'] = bcrypt($input['password']);

            $user = User::create($input);
            $success['user'] = $user;

            return response()->json([$success, 'user registered successfully'], 201);
        } catch (QueryException $exception) {

            return response()->json(['error' => 'Database error: ' . $exception->getMessage()], 500);
        } catch (\Exception $exception) {

            return response()->json(['error' => 'An unexpected error occurred'], 500);
        }
    }

    public function getUser()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json(['error' => 'User not found'], 403);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }

        return response()->json(['data' => $user, 'message' => 'User data retrieved'], 200);
    }
}
