<?php declare(strict_types=1);

namespace Token;

use Cache\InMemoryCache;
use Clock\Clock;
use Clock\ClockInterface;
use DateInterval;
use DateTimeInterface;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

class GoogleAccessToken extends JWTAccessToken implements AccessTokenInterface
{
    public function __construct(
        string                                              $scope,
        null|string                                         $projectId = null,
        null|string                                         $clientEmail = null,
        OpenSSLAsymmetricKey|OpenSSLCertificate|string|null $privateKey = null,
        null|string                                         $privateKeyId = null,

        /**
         * @link https://cloud.google.com/iam/docs/keys-create-delete
         */
        null|string                                         $keyFile = null,

        null|string|int|DateInterval|DateTimeInterface      $exp = 'PT1H',
        null|string|int|DateInterval|DateTimeInterface      $iat = 'PT1M',

        /**
         * (Algorithm) Header Parameter Value for JWS
         * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
         */
        string                                              $algorithm = 'RS256',

        ClockInterface                                      $clock = new Clock,
        CacheInterface                                      $cache = new InMemoryCache,
        string                                              $cachePrefix = 'google.access.token:'
    )
    {
        if (false === is_null($keyFile)) {
            [
                'project_id' => $projectId, 'private_key' => $privateKey,
                'private_key_id' => $privateKeyId, 'client_email' => $clientEmail
            ] = $this->readServiceAccountData($keyFile);
        }

        parent::__construct(
            payload: [
                'iss' => $clientEmail,
                'sub' => $clientEmail,
                'exp' => $exp,
                'iat' => $iat,
                'scope' => $scope
            ],
            algorithm: $algorithm,
            privateKey: $privateKey,
            privateKeyId: $privateKeyId,
            projectId: $projectId,
            clock: $clock,
            cache: $cache,
            cachePrefix: $cachePrefix
        );
    }

    public function getProjectId(): string
    {
        return $this->projectId;
    }

    #[ArrayShape([
        'project_id' => "string",
        'private_key' => "string",
        'private_key_id' => "string",
        'client_email' => "string"
    ])]
    protected function readServiceAccountData(string $serviceAccountKeyFile): array
    {
        if (file_exists($serviceAccountKeyFile) === false) {
            throw new RuntimeException(sprintf('File not exists to get key: %s', $serviceAccountKeyFile));
        }

        if (($serviceAccountKeyFileContent = file_get_contents($serviceAccountKeyFile)) === false) {
            throw new RuntimeException(sprintf('Error while get key from file: %s', $serviceAccountKeyFile));
        }

        $serviceAccountData = json_decode($serviceAccountKeyFileContent, true);

        if (($serviceAccountData['type'] ?? null) !== 'service_account') {
            throw new InvalidArgumentException('Invalid service account key.');
        }

        return $serviceAccountData;
    }
}
