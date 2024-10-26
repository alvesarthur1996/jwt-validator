<?php

namespace IBLTech\JwtValidator\Middlewares;

use Carbon\Carbon;
use Closure;
use Exception;
use IBLTech\JwtValidator\Traits\IBLTechJWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Log;

class ValidateStatefulJWT
{
    use IBLTechJWT;

    private $MISSING_TOKEN = ['message' => 'Unauthorized. Authorization token missing.'];
    private $INVALID_TOKEN = ['message' => 'Unauthorized. Invalid or expired token.'];

    public function handle(Request $request, Closure $next)
    {
        try {
            $token = $request->bearerToken();

            if (!$token) return Response::json($this->MISSING_TOKEN, 401);

            $decoded = $this->decode_token($token);

            if (!$decoded)
                return Response::json($this->INVALID_TOKEN, 401);
            $exp = 60;
            $exp_config = @array_filter(explode(',', @$decoded->user->permissions->permissions ?? []), fn($item) => preg_match('/^exp:\d+$/', $item))[0];

            if (!is_null($exp_config))
                $exp = (int) (@explode(':', $exp_config)[1] ?? 60);

            $data = $request->json()->all();
            $data['jwt_credentials'] = (array) $decoded;
            $request->json()->replace($data);

            $decoded->iat = Carbon::now()->timestamp;
            $decoded->exp = Carbon::now()->addMinutes($exp)->timestamp;
            $response = $next($request);
            $response->header('Session-Jwt', $this->create_token((array) $decoded));

            return $response;
        } catch (Exception $e) {
            Log::error(
                $e->getMessage(),
                [
                    'Class' => self::class,
                    'Line' => $e->getLine(),
                    'Trace' => $e->getTraceAsString()
                ]
            );
            return Response::json($this->INVALID_TOKEN, 401);
        }
    }
}
