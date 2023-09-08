<?php

namespace App\Http\Controllers;


use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use function Laravel\Prompts\password;
use function PHPUnit\Framework\once;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email:rfc,dns|max:255|unique:users,email',
            'password' => 'required|string|min:8|max:32',
            'identity_card' => 'required|image|mimes:jpg,png'
        ]);

        $name = time().$request->file('identity_card')->getClientOriginalName();
        $path = $request->file('identity_card')->move('images/identity-cards', $name)->getPath();

        $user = User::query()->create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
            'identity_card' => $path.'/'.$name
        ]);

        return response()->json([
            'rc' => 201,
            'message' => 'Successfully create',
            'data' => $user->refresh()
        ], 201);
    }

    /**
     * @throws \Exception
     */
    public function login(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email:rfc,dns',
            'password' => 'required|string',
        ]);

        $user = User::query()->where('email', $request->get('email'))->first();
        if (!$user)
            return response()->json(['message' => 'Incorrect email or password'], 401);

        $isValidPassword = Hash::check($request->get('password'), $user->password);
        if (!$isValidPassword)
            return response()->json(['message' => 'Incorrect email or password'], 401);

        $user->update([
            'api_token' => bin2hex(random_bytes(64))
        ]);

        return response()->json([
            'rc' => 200,
            'message' => 'Successfully',
            'data' => $user->makeVisible('api_token')
        ]);
    }

    public function logout() {
        $user = User::query()->find(auth()->user()->getAuthIdentifier());

        $user->update([
            'api_token' => null
        ]);

        return response()->json([
            'rc' => 200,
            'message' => 'Successfully',
            'data' => null
        ]);
    }
}
