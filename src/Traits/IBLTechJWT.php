<?php

namespace IBLTech\JwtValidator\Traits;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

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
