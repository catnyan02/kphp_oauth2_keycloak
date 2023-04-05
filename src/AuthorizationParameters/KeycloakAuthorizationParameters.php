<?php

namespace nyan02\kphp_oauth2_client\AuthorizationParameters;

class KeycloakAuthorizationParameters implements AuthorizationParametersInterface
{
    public string $response_type;
    public string $approval_prompt;
    public string $client_id;
    public ?string $redirect_uri;
    public string $state;
    public ?string $version;
    public string $scope;
    public ?string $code_challenge_method;
    public ?string $code_challenge;

    /**
     * Needed in order to use KPHP JsonEncoder.
     *
     */
    public function __construct(string $response_type, string $approval_prompt, string $client_id, string $redirect_uri, string $state,
                                string $scope, ?string $version){

        $this->response_type = $response_type;
        $this->approval_prompt = $approval_prompt;
        $this->client_id = $client_id;
        $this->redirect_uri = $redirect_uri;
        $this->scope = $scope;
        $this->state = $state;
        $this->version = $version;

    }

    /**
     * Builds the authorization URL's query string.
     *
     * @return string Query string
     */
    public function getAuthorizationQuery()
    {
        return http_build_query(to_array_debug($this), '', '&', \PHP_QUERY_RFC3986);
    }
}