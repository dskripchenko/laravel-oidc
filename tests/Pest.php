<?php

declare(strict_types=1);

use Dskripchenko\Oidc\Tests\TestCase;

require_once __DIR__.'/Support/helpers.php';

pest()->extend(TestCase::class)->in('Feature');
