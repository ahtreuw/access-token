<?php declare(strict_types=1);

namespace Token;

interface AccessTokenInterface
{
    public function getToken(): string;

    public function getProjectId(): null|string;
}