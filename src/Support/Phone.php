<?php

namespace Tenox\Connect\Support;

final class Phone
{
    public static function normalize(?string $value): ?string
    {
        $digits = preg_replace('/[\s\-()]/', '', (string) $value);

        if (! preg_match('/^(?:\+?976)?[6-9]\d{7}$/', $digits)) {
            return null;
        }

        return '+976'.substr($digits, -8);
    }

    /**
     * @return list<string>
     */
    public static function variants(?string $value): array
    {
        $normalized = self::normalize($value);
        if (! $normalized) {
            return [];
        }

        $local = substr($normalized, -8);

        return [$normalized, $local, '976'.$local];
    }
}
