<?php

namespace Idaas\Passport\Bridge;

use DateTimeImmutable;
use Idaas\OpenID\Encording\SecondBasedDateConversion;
use Idaas\OpenID\Entities\AccessTokenEntityInterface;
use Laravel\Passport\Bridge\AccessToken as BridgeAccessToken;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class AccessToken extends BridgeAccessToken implements AccessTokenEntityInterface
{

    protected $claims;
    protected ?string $issuer = null;

    private $oauthPrivateKey;

    public function __construct($userIdentifier, array $scopes, ClientEntityInterface $client, array $claims = [])
    {
        parent::__construct($userIdentifier, $scopes, $client);

        $this->claims = $claims;
    }

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ClaimEntityInterface[]
     */
    public function getClaims()
    {
        return $this->claims;
    }

    public function setIssuer(string $issuer)
    {
        $this->issuer = $issuer;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function setPrivateKey(CryptKey $privateKey)
    {
        parent::setPrivateKey($privateKey);

        $this->oauthPrivateKey = $privateKey;
    }

    private function buildJWT()
    {
        $this->initJwtConfiguration();

        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->oauthPrivateKey->getKeyContents(), $this->oauthPrivateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty')
        );

        $builder = $configuration->builder(new ChainedFormatter(
            new UnifyAudience(),
            new SecondBasedDateConversion()
        ))
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('client_id', $this->client->getIdentifier())
            ->withClaim('token_use', 'access')
            ->withClaim('scopes', $this->getScopes());

        if (method_exists($this->oauthPrivateKey, 'getKid')) {
            $builder->withHeader('kid', $this->oauthPrivateKey->getKid());
        }

        if ($this->issuer) {
            $builder->issuedBy($this->issuer);
        }

        return $builder->getToken($configuration->signer(), $configuration->signingKey());
    }

    public function __toString()
    {
        return $this->buildJWT()->toString();
    }
}
