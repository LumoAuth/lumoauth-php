<?php

declare(strict_types=1);

namespace LumoAuth\Tests\Support;

/** Locates sdk-contract/ (sibling of sdk-php in the umbrella checkout, or LUMO_SDK_CONTRACT). */
final class ContractFiles
{
    public static function dir(): ?string
    {
        $env = getenv('LUMO_SDK_CONTRACT');
        $candidates = array_filter([$env !== false ? $env : null, dirname(__DIR__, 5) . '/sdk-contract']);
        foreach ($candidates as $c) {
            if (is_file($c . '/routes.json')) {
                return $c;
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    public static function load(string $file): array
    {
        $dir = self::dir();
        if ($dir === null) {
            throw new \RuntimeException('sdk-contract not found');
        }

        return (array) json_decode((string) file_get_contents($dir . '/' . $file), true, 512, JSON_THROW_ON_ERROR);
    }
}
