<?php

namespace IBLTech\JwtValidator\Traits;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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
}
