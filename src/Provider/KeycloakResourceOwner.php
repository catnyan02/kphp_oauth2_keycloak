<?php

namespace nyan02\kphp_oauth2_client\Provider;

use nyan02\kphp_oauth2_client\Provider\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw JSON response
     *
     * @var     string
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param string $response
     */
    public function __construct($response = '{}')
    {
        $this->response = $response;
    }

    /**
     * Get resource owner id
     *
     * @return string
     */
    public function getId()
    {
        $response = json_decode($this->response, true);
        return \array_key_exists('sub', $response) ? (string) $response['sub'] : "";
    }

    /**
     * Get resource owner email
     *
     * @return ?string
     */
    public function getEmail()
    {
        $response = json_decode($this->response, true);
        return \array_key_exists('email', $response) ? (string) $response['email'] : null;
    }

    /**
     * Get resource owner name
     *
     * @return ?string
     */
    public function getName()
    {
        $response = json_decode($this->response, true);
        return \array_key_exists('name', $response) ? (string) $response['name'] : null;
    }

    public function toJSON(): string
    {
        return $this->response;
    }
}