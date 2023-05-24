<?php declare(strict_types=1);

namespace Token;

use Cache\InMemoryCache;
use Clock\Clock;
use Clock\ClockException;
use Clock\ClockExceptionInterface;
use Clock\ClockInterface;
use DateInterval;
use DateTimeInterface;
use Exception;
use Firebase\JWT\JWT;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Psr\SimpleCache\CacheException;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * JSON Web Token (JWT)
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7519
 */
class JWTAccessToken implements AccessTokenInterface
{
    private string|null $cacheKey = null;

    public function __construct(

        /**
         * Payload for JWT token
         *
         * @link https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
         *
         * The "iss" (issuer) claim identifies the principal that issued the JWT.
         * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
         * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
         * The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
         * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
         * The "iat" (issued at) claim identifies the time at which the JWT was issued.
         * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
         */
        #[ArrayShape([
            'iss' => "null|string",
            'sub' => "null|string",
            'aud' => "null|string",
            'exp' => "null|string|int|\DateInterval|\DateTimeInterface",
            'nbf' => "null|string|int|\DateInterval|\DateTimeInterface",
            'iat' => "null|string|int|\DateInterval|\DateTimeInterface",
            'jti' => "null|string",
            'scope' => "null|string",
        ])]
        protected array $payload = [],

        /**
         * (Algorithm) Header Parameter Value for JWS
         * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
         */
        protected string $algorithm = 'RS256',

        /**
         * An array with header elements to attach
         * @link https://github.com/firebase/php-jwt#example-encodedecode-headers
         */
        protected array $headers = [],

        /**
         * The secret key.
         */
        protected OpenSSLAsymmetricKey|OpenSSLCertificate|string|null $privateKey = null,

        /**
         * The id of secret key.
         */
        protected null|string $privateKeyId = null,

        /**
         * @link https://www.php.net/manual/en/function.openssl-pkey-get-private.php
         */
        protected null|string $privateKeyFile = null,

        /**
         * @link https://www.php.net/manual/en/function.openssl-pkey-get-private.php
         */
        protected null|string $passphrase = null,

        protected null|string $projectId = null,

        protected ClockInterface $clock = new Clock,
        protected CacheInterface $cache = new InMemoryCache,
        protected string $cachePrefix = 'jwt.access.token:'
    )
    {
    }

    /**
     * @throws CacheException
     * @throws ClockExceptionInterface
     */
    public function getToken(): string
    {
        $cacheKey = $this->cachePrefix . $this->getTokenCacheKey();

        if ($this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }

        $token = $this->createToken();

        $this->cache->set($cacheKey, $token, $this->getExpiryInterval());

        return $token;
    }

    protected function getTokenCacheKey(): string
    {
        return $this->cacheKey ??= md5(serialize($this->payload));
    }

    /**
     * @throws ClockExceptionInterface
     */
    protected function createToken(): string
    {
        return JWT::encode(
            $this->getPayload(),
            $this->getPrivateKey(),
            $this->algorithm,
            $this->privateKeyId,
            $this->headers
        );
    }

    /**
     * @throws ClockExceptionInterface
     */
    protected function getPayload(): array
    {
        $payload = $this->payload;

        array_key_exists('exp', $payload) && $payload['exp'] = $this->parseToTime($payload['exp'], false);
        array_key_exists('nbf', $payload) && $payload['nbf'] = $this->parseToTime($payload['nbf'], false);
        array_key_exists('iat', $payload) && $payload['iat'] = $this->parseToTime($payload['iat'], true);

        return array_filter($payload, 'trim');
    }

    /**
     * @throws ClockExceptionInterface
     */
    protected function getExpiryInterval(): DateInterval|int
    {
        if (array_key_exists('exp', $this->payload) === false) {
            return 300; // 5 min
        }
        return $this->parseToTime($this->payload['exp'], false) - $this->clock->now()->getTimestamp();
    }

    protected function getPrivateKey(): OpenSSLAsymmetricKey|OpenSSLCertificate|string
    {
        if (is_object($this->privateKey)) {
            return $this->getPrivateKeyFromObject();
        }
        if (is_string($this->privateKey)) {
            return $this->getPrivateKeyFromString();
        }
        if (is_string($this->privateKeyFile)) {
            return $this->getPrivateKeyFromFile();
        }
        throw new InvalidArgumentException('Invalid value for private key.');
    }

    protected function getPrivateKeyFromObject(): OpenSSLAsymmetricKey|OpenSSLCertificate|string
    {
        if (is_null($this->passphrase)) {
            return $this->privateKey;
        }
        if (($privateKey = openssl_pkey_get_private($this->privateKey, $this->passphrase)) === false) {
            throw new RuntimeException(sprintf('Error while get key from object: %s', $this->privateKey::class));
        }
        $this->passphrase = null;
        return $this->privateKey = $privateKey;
    }

    protected function getPrivateKeyFromString(): OpenSSLAsymmetricKey|OpenSSLCertificate|string
    {
        if (is_null($this->passphrase)) {
            return $this->privateKey;
        }
        if (($privateKey = openssl_pkey_get_private($this->privateKey, $this->passphrase)) === false) {
            throw new RuntimeException('Error while get key from string');
        }
        $this->passphrase = null;
        return $this->privateKey = $privateKey;
    }

    protected function getPrivateKeyFromFile(): OpenSSLAsymmetricKey|OpenSSLCertificate|string
    {
        if (file_exists($this->privateKeyFile) === false) {
            throw new RuntimeException(sprintf('File not exists to get key: %s', $this->privateKeyFile));
        }
        if (($privateKeyFileContent = file_get_contents($this->privateKeyFile)) === false) {
            throw new RuntimeException(sprintf('Error while get key from file: %s', $this->privateKeyFile));
        }
        if (($privateKey = openssl_pkey_get_private($privateKeyFileContent, $this->passphrase)) === false) {
            throw new RuntimeException(sprintf('Error while get key from: %s', $this->privateKeyFile));
        }
        $this->passphrase = null;
        return $this->privateKey = $privateKey;
    }

    /**
     * @throws ClockExceptionInterface
     */
    protected function parseToTime(int|string|DateInterval|DateTimeInterface $time, bool $invert): int
    {
        if (is_string($time)) {
            $time = $this->parseStrToTime($time);
        }
        if (is_int($time)) {
            return $this->parseIntToTime($time, $invert);
        }
        if ($time instanceof DateInterval) {
            if ($invert) {
                return $this->clock->now()->sub($time)->getTimestamp();
            }
            return $this->clock->now()->add($time)->getTimestamp();
        }
        return $time->getTimestamp();
    }

    /**
     * @throws ClockExceptionInterface
     */
    protected function parseIntToTime(int $time, bool $invert): int
    {
        if (31536000 < $time) {
            return $time;
        }
        if ($invert && 0 < $time) {
            return $this->clock->now()->getTimestamp() - $time;
        }
        return $this->clock->now()->getTimestamp() + $time;
    }

    /**
     * @throws ClockException
     */
    protected function parseStrToTime(string $time): int|DateInterval
    {
        if (str_starts_with($time, 'P')) {
            try {
                return new DateInterval($time);
            } catch (Exception $exception) {
                throw new ClockException($exception);
            }
        }
        return $this->clock->with($time)->now()->getTimestamp();
    }

    public function getProjectId(): null|string
    {
        return $this->projectId;
    }
}
