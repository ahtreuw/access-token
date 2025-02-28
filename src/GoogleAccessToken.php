<?php declare(strict_types=1);

namespace Token;

use InvalidArgumentException;
use RuntimeException;

class GoogleAccessToken extends AccessToken implements AccessTokenInterface
{
    private const SERVICE_ACCOUNT = 'service_account';
    private const GOOGLE_APPLICATION_CREDENTIALS = 'GOOGLE_APPLICATION_CREDENTIALS';
    private const FILE_NOT_EXISTS = 'File not exists to get key: %s';
    private const ERROR_GET_FILE_CONTENTS = 'Error while get key from file: %s';
    private const INVALID_SERVICE_ACCOUNT_KEY = 'Invalid service account key.';

    public null|string $type = null;
    public null|string $project_id = null;
    public null|string $client_email = null;
    public null|string $client_id = null;
    public null|string $auth_uri = null;
    public null|string $token_uri = null;
    public null|string $auth_provider_x509_cert_url = null;
    public null|string $client_x509_cert_url = null;
    public null|string $universe_domain = null;
    protected null|array $scopes = [];

    public function __construct(string $serviceAccountFilename = null, mixed ...$data)
    {
        parent::__construct(...$data);
        $this->init($serviceAccountFilename);
    }

    public function getScopes(): ?array
    {
        return $this->scopes;
    }

    public function setScopes(string ...$scopes): void
    {
        $this->scopes = $scopes;
    }

    protected function generatePayload(): array
    {
        if (is_null($this->scopes)) {
            throw new RuntimeException(sprintf(self::CANNOT_GENERATE_TOKEN, 'payload.scopes'));
        }
        $now = time();
        return [
            'iss' => $this->client_email,
            'sub' => $this->client_email,
            'iat' => $now,
            'exp' => $now + 3600,
            'scope' => implode(' ', $this->scopes)
        ];
    }

    public function init(null|string $serviceAccountFilename = null): void
    {
        $serviceAccountFilename = $serviceAccountFilename ?? getenv(self::GOOGLE_APPLICATION_CREDENTIALS);

        if (file_exists($serviceAccountFilename) === false) {
            throw new RuntimeException(sprintf(self::FILE_NOT_EXISTS, $serviceAccountFilename));
        }

        if (($serviceAccountKeyFileContent = file_get_contents($serviceAccountFilename)) === false) {
            throw new RuntimeException(sprintf(self::ERROR_GET_FILE_CONTENTS, $serviceAccountFilename));
        }

        $serviceAccountData = json_decode($serviceAccountKeyFileContent, true);

        if (($serviceAccountData['type'] ?? null) !== self::SERVICE_ACCOUNT) {
            throw new InvalidArgumentException(self::INVALID_SERVICE_ACCOUNT_KEY);
        }

        foreach ($serviceAccountData as $property => $value) {
            property_exists($this, $property) && $this->$property = $value;
        }
    }
}
