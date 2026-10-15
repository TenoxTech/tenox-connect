<?php

namespace Tenox\Connect;

final class TenoxIdentity
{
    /**
     * @param  list<array{id: string, reg_no: string, name: string, role: string}>  $companies
     */
    public function __construct(
        public readonly string $id,
        public readonly ?string $name,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly ?string $phone,
        public readonly bool $phoneVerified,
        public readonly ?string $picture,
        public readonly array $companies,
        public readonly array $claims,
        public readonly ?string $accessToken = null,
        public readonly ?string $refreshToken = null,
    ) {}

    public static function fromClaims(array $claims, ?string $accessToken = null, ?string $refreshToken = null): self
    {
        return new self(
            id: (string) $claims['sub'],
            name: $claims['name'] ?? null,
            email: isset($claims['email']) ? mb_strtolower($claims['email']) : null,
            emailVerified: (bool) ($claims['email_verified'] ?? false),
            phone: $claims['phone_number'] ?? null,
            phoneVerified: (bool) ($claims['phone_number_verified'] ?? false),
            picture: $claims['picture'] ?? null,
            companies: array_values($claims['companies'] ?? []),
            claims: $claims,
            accessToken: $accessToken,
            refreshToken: $refreshToken,
        );
    }

    public function verifiedEmail(): ?string
    {
        return $this->emailVerified ? $this->email : null;
    }

    public function verifiedPhone(): ?string
    {
        return $this->phoneVerified ? $this->phone : null;
    }

    public function company(string $tenoxCompanyId): ?array
    {
        foreach ($this->companies as $company) {
            if ($company['id'] === $tenoxCompanyId) {
                return $company;
            }
        }

        return null;
    }
}
