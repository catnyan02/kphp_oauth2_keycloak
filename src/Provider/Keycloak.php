<?php

namespace nyan02\kphp_oauth2_client\Provider;

use Exception;
use nyan02\kphp_jwt\JWT;
use nyan02\kphp_oauth2_client\AuthorizationParameters\KeycloakAuthorizationParameters;
use nyan02\kphp_oauth2_client\Grant\AbstractGrant;
use nyan02\kphp_oauth2_client\Provider\AbstractProvider;
use nyan02\kphp_oauth2_client\Token\AccessToken;
use nyan02\kphp_oauth2_client\Token\AccessTokenInterface;
use nyan02\kphp_oauth2_client\Tool\BearerAuthorizationTrait;
use nyan02\kphp_oauth2_client\Exceptions\EncryptionConfigurationException;
use UnexpectedValueException;


class Keycloak extends AbstractProvider
{
    /**
     * Keycloak URL, eg. http://localhost:8080/auth.
     *
     * @var ?string
     */
    public $authServerUrl = null;

    /**
     * Realm name, eg. demo.
     *
     * @var ?string
     */
    public $realm = null;

    /**
     * Encryption algorithm.
     *
     * You must specify supported algorithms for your application. See
     * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
     * for a list of spec-compliant algorithms.
     *
     * @var ?string
     */
    public $encryptionAlgorithm = null;

    /**
     * Encryption key.
     *
     * @var ?string
     */
    public $encryptionKey = null;

    /**
     * Keycloak version.
     *
     * @var ?string
     */
    public $version = null;

    public function setAuthServerUrl($authServerUrl){
        $this->authServerUrl = $authServerUrl;
    }

    public function setRealm($realm){
        $this->realm = $realm;
    }

    public function getAuthorizationParameters(?string $state = null, ?string $scope = null, ?string $redirectUri = null,
                                               ?string $version = null): KeycloakAuthorizationParameters
    {
        $version = $version ?: $this->version;

        $state = $state ?: $this->getRandomState();
        $redirectUri = $redirectUri ?: $this->redirectUri;

        // Default scopes MUST be included for OpenID Connect.
        // Additional scopes MAY be added by constructor or option.

        $scopes = $this->getDefaultScopes();

        $scopes = $scope? $scopes . $scope : $scopes;


        $params = new KeycloakAuthorizationParameters("code", 'auto', $this->clientId, $redirectUri, $state, $scopes,
            $version);

        $this->state = $params->state;

        $pkceMethod = $this->getPkceMethod();

        if (!empty($pkceMethod)) {
            $this->pkceCode = $this->getRandomPkceCode();
            if ($pkceMethod === self::PKCE_METHOD_S256) {
                $params->code_challenge = trim(
                    strtr(base64_encode(hash('sha256', $this->pkceCode, true)), '+/', '-_'), '=');
            } elseif ($pkceMethod === self::PKCE_METHOD_PLAIN) {
                $params->code_challenge = $this->pkceCode;
            } else {
                throw new \Exception('Unknown PKCE method "' . $pkceMethod . '".');
            }
            $params->code_challenge_method = $pkceMethod;
        }
        return $params;
    }


    /**
     * Attempts to decrypt the given response.
     *
     * @param  ?string $response
     *
     * @return string
     */
    public function decryptResponse($response)
    {
        if (is_null($response)){
            return "";
        }
        if ($this->usesEncryption()) {
            $res = json_encode(
                JWT::decode(
                    $response,
                    (string) $this->encryptionKey,
                    (string) $this->encryptionAlgorithm
                )
            );
            return $res? $res : "";
        }

        return $response;
    }

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/auth';
    }

    /**
     * Get access token url to retrieve token
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param  AccessTokenInterface $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessTokenInterface $token): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/userinfo';
    }

    /**
     * Creates base url from provider configuration.
     *
     * @return string
     */
    protected function getBaseUrlWithRealm()
    {
        return $this->authServerUrl.'/realms/'.$this->realm;
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return string
     */
    protected function getDefaultScopes(): string
    {
        $scopes = 'profile email';
        if ($this->validateGteVersion('20.0.0')) {
            $scopes = 'openid';
        }
        return $scopes;
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ','
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Returns a prepared request for requesting an access token.
     *
     * @return string
     */
    protected function makeAccessTokenRequest(AbstractGrant $grant)
    {
        $method = $this->getAccessTokenMethod();
        $url = $this->getAccessTokenUrl($grant);
        $res = $this->decryptResponse($this->getOptionProvider()->makeRequest($method, $url, $grant));

        return $res;
    }


    /**
     * Check a provider response for errors.
     *
     * @param  string $data Parsed response data
     */
    protected function checkResponse($data)
    {

        $parsed_data = json_decode($data, true);

        if (empty($parsed_data['error'])) {
            return;
        }

        $error = $parsed_data['error'];

        if (!empty($parsed_data['error_description'])) {
            $error.=': '.$parsed_data['error_description'];
        }

        throw new \Exception((string) $error, 0);
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param string $response
     * @param AccessTokenInterface $token
     * @return KeycloakResourceOwner
     */
    protected function createResourceOwner($response, $token)
    {
        return new KeycloakResourceOwner($response);
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessTokenInterface $token
     * @return KeycloakResourceOwner
     *
     */
    public function getResourceOwner(AccessTokenInterface $token)
    {
        $response = $this->fetchResourceOwnerDetails($token);
        $response = $this->decryptResponse($response);

        return $this->createResourceOwner($response, $token);
    }


    /**
     * Updates expected encryption algorithm of Keycloak instance.
     *
     * @param string  $encryptionAlgorithm
     *
     * @return \nyan02\kphp_oauth2_client\Provider\Keycloak
     */
    public function setEncryptionAlgorithm($encryptionAlgorithm)
    {
        $this->encryptionAlgorithm = $encryptionAlgorithm;

        return $this;
    }

    /**
     * Updates expected encryption key of Keycloak instance.
     *
     * @param string  $encryptionKey
     *
     * @return Keycloak
     */
    public function setEncryptionKey($encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;

        return $this;
    }

    /**
     * Updates expected encryption key of Keycloak instance to content of given
     * file path.
     *
     * @param string  $encryptionKeyPath
     *
     * @return Keycloak
     */
    public function setEncryptionKeyPath($encryptionKeyPath)
    {
        $this->encryptionKey = file_get_contents($encryptionKeyPath);
        return $this;
    }

    /**
     * Updates the keycloak version.
     *
     * @param string  $version
     *
     * @return Keycloak
     */
    public function setVersion($version)
    {
        $this->version = $version;

        return $this;
    }

    /**
     * Checks if provider is configured to use encryption.
     *
     * @return bool
     */
    public function usesEncryption()
    {
        return (bool) $this->encryptionAlgorithm && $this->encryptionKey;
    }

    /**
     * Validate if version is greater or equal
     *
     * @param string $version
     * @return bool
     */
    private function validateGteVersion($version)
    {
        return (isset($this->version) && ($this->version >= $version));
    }
}