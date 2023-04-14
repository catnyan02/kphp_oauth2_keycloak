This package provides Keycloak OAuth 2.0 support for the KPHP

### Installation
To install, use composer:

```composer require nyan02/kphp_oauth2_keycloak ```

### Usage
Usage is similar to KPHP OAuth client, using nyan02\kphp_oauth2_client\Provider\Keycloak 
as the provider.

You need to create a new Provider object specifying keycloak-client-id,
keycloak-client-secret and callback-url.

The main difference from generic provider class is that you have to set
Keycloak specific parameters: AuthServerUrl and Realm. You can also set
your Keycloak version (this will change the default scopes).

If you've configured your Keycloak instance to use encryption, 
there are some advanced options available to you.
You can configure the provider to use the same encryption algorithm and 
to use the expected decryption public key or certificate. You can set
the key either by specifying the path or by directly passing the contents.

You can see the example below.
### Authorization Code Example
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

### Authorization Code Flow
After configuring provider we want to get Authorization Code. We use
method getAuthorizationParameters() to get parameters from the provider
including permission scopes and other info needed for generating
AuthorizationUrl. 

Next we generate AuthorizationUrl using method getAuthorizationUrl($params)
and passing parameters we've got before. Now that we have the Url we can
redirect the user to Authorization page of provider.

Once we've got Authorization Code we create a placeholder class for it

```new AuthorizationCode($provider->getClientId(), $provider->getClientSecret(), $provider->getRedirectUri())```

And pass it to getAccessToken method together with the code we've got.

```$token = $provider->getAccessToken($grant, ['code' => $_GET['code']]);```

Now we have the Access Token to Resource.

### Getting ResourceOwner Information
With Access Token we can now access Resource Owner's information.

```$user = $provider->getResourceOwner($token);```

Implemented methods for KeycloakResourceOwner are getId(), getEmail(), getName() and
toJSON(). toJSON() allows getting values of custom configured
by the keycloak server administrator fields.
