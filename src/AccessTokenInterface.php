<?php declare(strict_types=1);

namespace Token;

use Throwable;

interface AccessTokenInterface
{
    /**
     * @throws Throwable
     */
    public function generateToken(): string;

    /**
     * @throws Throwable
     */
    public function decodeToken(string $token): array;
}
