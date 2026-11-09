<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Contracts\GroupSync;
use Dskripchenko\Oidc\Contracts\OutboundHttp;
use Dskripchenko\Oidc\Contracts\SubjectUsers;
use Dskripchenko\Oidc\Defaults\EloquentSubjectUsers;
use Dskripchenko\Oidc\Defaults\NullGroupSync;
use Dskripchenko\Oidc\Defaults\PlainOutboundHttp;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Schema;

it('binds the defaults', function (): void {
    expect(app(SubjectUsers::class))->toBeInstanceOf(EloquentSubjectUsers::class)
        ->and(app(GroupSync::class))->toBeInstanceOf(NullGroupSync::class)
        ->and(app(OutboundHttp::class))->toBeInstanceOf(PlainOutboundHttp::class)
        ->and(config('oidc.api_token_types'))->toBe('at+jwt');
});

it('finds the person by the issuer and subject columns', function (): void {
    config([
        'database.default' => 'testing',
        'database.connections.testing' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
        'oidc.users.model' => User::class,
    ]);
    Schema::create('users', static function (Blueprint $table): void {
        $table->id();
        $table->string('oidc_issuer')->nullable();
        $table->string('oidc_subject')->nullable();
    });
    User::query()->insert([
        ['oidc_issuer' => TEST_ISSUER, 'oidc_subject' => 'u-1'],
        ['oidc_issuer' => 'https://elsewhere.example.test', 'oidc_subject' => 'u-2'],
    ]);
    $users = app(SubjectUsers::class);

    expect($users->find(TEST_ISSUER, 'u-1')?->getAuthIdentifier())->toBe(1)
        ->and($users->find(TEST_ISSUER, 'u-2'))->toBeNull();

    config(['oidc.users.model' => stdClass::class]);
    expect(fn () => $users->find(TEST_ISSUER, 'u-1'))->toThrow(LogicException::class);
});
