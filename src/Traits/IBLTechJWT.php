<?php

namespace IBLTech\JwtValidator\Traits;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

trait IBLTechJWT
{
    public static function create_token($payload)
    {
        return JWT::encode($payload, env('JWT_SECRET'), 'HS256');
    }

    public static function decode_token($jwt)
    {
        return JWT::decode($jwt, new Key(env('JWT_SECRET'), 'HS256'));
    }

    public static function get_credentials(Request $request)
    {
        $credentials = @$request->jwt_credentials ?? @$request->json('jwt_credentials');

        return $credentials;
    }
}
