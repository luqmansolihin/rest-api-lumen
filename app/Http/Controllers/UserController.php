<?php

namespace App\Http\Controllers;

use Illuminate\Validation\UnauthorizedException;

class UserController extends Controller
{
    public function show($id)
    {
        if (auth()->user()->getAuthIdentifier() != $id)
            throw new UnauthorizedException();

        $user = auth()->user();
        return response()->json([
            'rc' => 200,
            'message' => 'Successfully',
            'data' => $user
        ]);
    }
}
