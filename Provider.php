<?php

namespace SocialiteProviders\FranceConnect;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\InvalidStateException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use Illuminate\Support\Facades\Log;

class Provider extends AbstractProvider
{
    /**
     * API URLs
     */
    public const PROD_BASE_URL = 'https://oidc.franceconnect.gouv.fr/api/v2';

    public const TEST_BASE_URL = 'https://fcp-low.integ01.dev-franceconnect.fr/api/v2';

    public const IDENTIFIER = 'FRANCECONNECT';

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'openid',
        'given_name',
        'family_name',
        'gender',
        'birthplace',
        'birthcountry',
        'email',
        'preferred_username',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * Return API Base URL.
     *
     * @return string
     */
    protected function getBaseUrl()
    {
        return config('app.env') === 'production' ? self::PROD_BASE_URL : self::TEST_BASE_URL;
    }

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['logout_redirect'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        //It is used to prevent replay attacks
        //Minimum 22 characters in v2 version
        $this->parameters['nonce'] = Str::random(25);

        return $this->buildAuthUrlFromBase($this->getBaseUrl().'/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->getBaseUrl().'/token';
    }

    /**
     * {@inheritdoc}
     * @throws \Exception
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getBaseUrl().'/token', [
            RequestOptions::HEADERS     => ['Content-Type' => 'application/x-www-form-urlencoded'],
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        Log::info("access token response ");
        Log::info((string) $response->getBody());

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'access_token')
        ));

        //store tokenId session for logout url generation
        $this->request->session()->put('fc_token_id', Arr::get($response, 'id_token'));

        return $user->setTokenId(Arr::get($response, 'id_token'))
            ->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        Log::info("get user by token");
        Log::info($token);

        $response = $this->getHttpClient()->get($this->getBaseUrl().'/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        Log::info("user by token response");
        Log::info((string) $response->getBody());

        // Verify signature of user info with the keys
        $keys = $this->getKeys();

        $user = $this->decodeJwt((string) $response->getBody(), $keys);

        Log::info("user");
        Log::info($user);

        return json_decode((string) $user, true);
    }

    private function getKeys()
    {
        $response = $this->getHttpClient()->get($this->getBaseUrl().'/jwks');

        return json_decode((string) $response->getBody(), true);
    }

    private function decodeJwt($jwt, $keys)
    {
        Log::info("key in decode : ");
        Log::info($keys['keys'][0]);
        // Using the first key retrieved: ES256 algorithm
        $formattedKey = $this->generatePemFromJwk($keys['keys'][0]);

        Log::info("formatted key");
        Log::info($formattedKey);

        // Set up JWT configuration
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($formattedKey),            // False private key that won't be needed for verification
            InMemory::plainText($formattedKey)  // Public key for verification
        );

        // Parse the token
        $token = $configuration->parser()->parse($jwt);

        // Validate the signature
        $isVerified = $configuration->validator()->validate(
            $token,
            new SignedWith(
                new Sha256(),
                InMemory::plainText($formattedKey)
            )
        );

        if ($isVerified) {
            // Token is valid, get the claims
            $claims = $token->claims()->all();
            Log::info("claims");
            Log::info($claims);
            return $claims;
        } else {
            // Invalid token
            Log::info("Invalid token");
        }
    }

    private function generatePemFromJwk($jwk) {
        $x = $this->base64url_decode($jwk['x']);
        $y = $this->base64url_decode($jwk['y']);

        // Build the uncompressed public key (04 indicates uncompressed)
        $publicKey = "\x04" . $x . $y;

        // Define the ASN.1 structure for the public key
        $asn1Structure = "\x30" . "\x59" . // SEQUENCE and length
            "\x30" . "\x13" . // SEQUENCE and length
            "\x06" . "\x07" . "\x2A" . "\x86" . "\x48" . "\xCE" . "\x3D" . "\x02" . "\x01" . // OBJECT IDENTIFIER (1.2.840.10045.2.1 - ecPublicKey)
            "\x06" . "\x08" . "\x2A" . "\x86" . "\x48" . "\xCE" . "\x3D" . "\x03" . "\x01" . "\x07" . // OBJECT IDENTIFIER (1.2.840.10045.3.1.7 - P-256 curve)
            "\x03" . "\x42" . "\x00" . $publicKey; // BIT STRING with public key

        // Convert to PEM format
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($asn1Structure), 64, "\n")
            . "-----END PUBLIC KEY-----";

        return $pem;
    }

    private function base64url_decode($data) {
        $base64 = strtr($data, '-_', '+/');
        return base64_decode($base64);
    }


    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'                     => $user['sub'],
            'given_name'             => $user['given_name'],
            'family_name'            => $user['family_name'],
            'gender'                 => $user['gender']
        ]);
    }

    /**
     *  Generate logout URL for redirection to FranceConnect.
     */
    public function generateLogoutURL()
    {
        $params = [
            'post_logout_redirect_uri' => $this->getConfig('logout_redirect'),
            'id_token_hint'            => $this->request->session()->get('fc_token_id'),
        ];

        return $this->getBaseUrl().'/logout?'.http_build_query($params);
    }
}
