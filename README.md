# Access token generator & decoder

Generate token with GoogleAccessToken for your Google client
```.env
GOOGLE_APPLICATION_CREDENTIALS: "/app/your-service-account.json"
```
```php
<?php

require 'vendor/autoload.php';

$googleServiceAccount = new Token\GoogleAccessToken;
$googleServiceAccount->setScopes(...scopes: 'https://www.googleapis.com/auth/pubsub');

$googleServiceAccount->generateToken();
```

Generate a token and decode an access token on the other side
```php
<?php

require 'vendor/autoload.php';

$serviceAccount = new Token\AccessToken(
    payload: [
        'iss' => 'it\'s me',
        'sub' => 'my-id'
    ]
);

// you can set your own keys in the Token\AccessToken constructor, this is (optional)
$serviceAccount->generateKeys();

// you can save your newly generated public key (optional), and your private too (and it's ID)
$publicKey = $serviceAccount->getPublicKey();

// your token to pass for example via Bearer
$token = $serviceAccount->generateToken();

// On the other side, you can use Your public key to decode the token
$otherServiceAccount = new Token\AccessToken(public_key: $publicKey);

// And here you get you're payload
$payload = $otherServiceAccount->decodeToken($token);
```