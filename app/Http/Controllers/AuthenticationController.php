<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Models\Student;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthenticationController extends Controller {
  public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'confirm_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json(
                [
                    'success' => false,
                    'message' => 'Ada masalah saat registrasi',
                    'data' => $validator->errors(),
                ]
            );
        }

        $password = bcrypt($request->password);
        $inputs = $request->all();
        $inputs['password'] = $password;
        $user = User::create($inputs);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(
            [
                'success' => true,
                'message' => 'Registrasi Berhasil',
                'data' => [
                    'user' => $user,
                    'token' => $token,
                ],
            ]
        );
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(
                [
                    'success' => false,
                    'message' => 'Ada masalah saat login',
                    'data' => $validator->errors(),
                ]
            );
        }

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();
            $token = $user->createToken('auth_token')->plainTextToken;
            return response()->json(
                [
                    'success' => true,
                    'message' => 'Login Berhasil',
                    'data' => [
                        'user' => $user,
                        'token' => $token,
                    ],
                ]
            );
        } else {
            return response()->json(
                [
                    'success' => false,
                    'message' => 'Login Gagal',
                    'data' => null,
                ]
            );
        }
    }

  public function logout() {
    auth()->user()->tokens()->delete();

    return response()->json([
      "message" => "Successfully logged out."
    ], Response::HTTP_OK);
  }

  public function getUser() {
    return response()->json([
      "user" => auth()->user()
    ], Response::HTTP_OK);
  }
}
