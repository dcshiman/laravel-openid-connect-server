<?php

namespace Idaas\Passport\Bridge;

use Idaas\OpenID\Repositories\AccessTokenRepositoryInterface;
use Idaas\Passport\Bridge\AccessToken;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\AccessTokenRepository as LaravelAccessTokenRepository;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class AccessTokenRepository extends LaravelAccessTokenRepository implements AccessTokenRepositoryInterface
{
    private string $issuer;
    private ?string $authCodeId;

    public function __construct(TokenRepository $tokenRepository, Dispatcher $events, string $issuer)
    {
        parent::__construct($tokenRepository, $events);

        $this->issuer = $issuer;
    }

    public function storeClaims(AccessTokenEntityInterface $token, array $claims)
    {
        $token = $this->tokenRepository->find($token->getIdentifier());
        $token->claims = $claims;
        $token->save();
    }

    public function setAuthCodeId($id) {
        $this->authCodeId = $id;
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        $accessToken = parent::getNewToken($clientEntity, $scopes, $userIdentifier);

        if (method_exists($accessToken, 'setIssuer')) {
            $accessToken->setIssuer($this->issuer);
        }

        if (method_exists($accessToken, 'setAuthCodeId')) {
            $accessToken->setAuthCodeId($this->authCodeId);
        }

        return $accessToken;
    }

    public function getAccessToken($id)
    {
        $token = $this->tokenRepository->find($id);

        $claims = ClaimEntity::fromJsonArray($token->claims ?? []);

        return new AccessToken(
            $token->user_id,
            collect($token->scopes)->map(function ($scope) {
                return new Scope($scope);
            })->toArray(),
            new Client('not used', 'not used', 'not used', false),
            $claims
        );
    }
}
