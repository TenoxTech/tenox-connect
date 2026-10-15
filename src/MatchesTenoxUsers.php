<?php

namespace Tenox\Connect;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Tenox\Connect\Support\Phone;

trait MatchesTenoxUsers
{
    public static function findForTenox(TenoxIdentity $identity, string $phoneColumn = 'phone', string $emailColumn = 'email'): ?static
    {
        /** @var Builder<static> $query */
        $query = static::query();

        if ($linked = (clone $query)->where('tenox_user_id', $identity->id)->first()) {
            return $linked;
        }

        $unlinked = fn () => (clone $query)->whereNull('tenox_user_id');

        if ($variants = Phone::variants($identity->verifiedPhone())) {
            if ($user = $unlinked()->whereIn($phoneColumn, $variants)->first()) {
                return $user;
            }
        }

        if ($email = $identity->verifiedEmail()) {
            if ($user = $unlinked()->whereRaw("LOWER({$emailColumn}) = ?", [$email])->first()) {
                return $user;
            }
        }

        return null;
    }

    public function linkTenox(TenoxIdentity $identity): void
    {
        /** @var Model $this */
        if ($this->getAttribute('tenox_user_id') !== $identity->id) {
            $this->forceFill(['tenox_user_id' => $identity->id])->save();
        }
    }
}
