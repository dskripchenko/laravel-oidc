<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Groups\RoleMapping;

it('reads group=role pairs and skips the broken ones', function (): void {
    expect(RoleMapping::pairs(' admins = admin, auditors=auditor,=x,y=, broken ,ops=Release Manager'))->toBe([
        ['group' => 'admins', 'role' => 'admin'],
        ['group' => 'auditors', 'role' => 'auditor'],
        ['group' => 'ops', 'role' => 'Release Manager'],
    ])->and(RoleMapping::pairs(''))->toBe([]);
});

it('gives a role to a member of one of its groups', function (): void {
    $change = RoleMapping::decide(['a', 'b'], ['x', 'b'], null);

    expect($change?->give)->toBeTrue()
        ->and($change?->takeOver)->toBeFalse()
        ->and($change?->group)->toBe('b');
});

it('takes over a role held by hand when the person joins its group', function (): void {
    $change = RoleMapping::decide(['a'], ['a'], false);

    expect($change?->give)->toBeTrue()->and($change?->takeOver)->toBeTrue();
});

it('takes back only a role the provider gave', function (): void {
    $change = RoleMapping::decide(['a', 'b'], ['x'], true);

    expect($change?->give)->toBeFalse()
        ->and($change?->group)->toBe('a')
        ->and(RoleMapping::decide(['a'], ['x'], false))->toBeNull()
        ->and(RoleMapping::decide(['a'], ['x'], null))->toBeNull()
        ->and(RoleMapping::decide(['a'], ['a'], true))->toBeNull();
});
