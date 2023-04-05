```
<?php

use nyan02\kphp_oauth2_client\Grant\AuthorizationCode;
use nyan02\kphp_oauth2_client\Provider\Keycloak;

require_once __DIR__ . '/vendor/autoload.php';

$provider = new Keycloak('{keycloak-client-id}',
    '{keycloak-client-secret}',
    'https://example.com/callback-url',
    );
    
$provider->setAuthServerUrl('https://example.com/auth');
$provider->setRealm('realm');
$provider->setVersion('20.0.1'); // optional
$provider->setEncryptionAlgorithm('RS256'); // optional
$provider->setEncryptionKeyPath('../key.pem'); // optional
$provider->setEncryptionKey('contents_of_key_or_certificate'); // optional

if (!isset($_GET['code'])) {

    $params = $provider->getAuthorizationParameters();
    $authUrl = $provider->getAuthorizationUrl($params);
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

} else {
    $grant = new AuthorizationCode($provider->getClientId(), $provider->getClientSecret(), $provider->getRedirectUri());
    $token = $provider->getAccessToken($grant, ['code' => $_GET['code']]);

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the user's details
        $user = $provider->getResourceOwner($token);

        // Use these details to create a new profile
        printf('Hello %s!', $user->getName());

    } catch (Exception $e) {
        exit('Failed to get resource owner: '.$e->getMessage());
    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();
}
```