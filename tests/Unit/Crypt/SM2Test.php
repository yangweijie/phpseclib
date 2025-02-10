<?php

declare(strict_types=1);

namespace phpseclib3\Tests\Unit\Crypt;


use phpseclib3\Crypt\SM2;
use phpseclib3\Crypt\SM2\PublicKey;
use phpseclib3\Tests\PhpseclibTestCase;

class SM2Test extends PhpseclibTestCase
{

    public function testEncrypt(){
        $sm2 = SM2::createKey();
        $this->assertEquals($sm2->getPublicKey()->encrypt('123'), '');
    }

    public function testDecrypt(){
        $sm2 = SM2::createKey();
        $encrypted = $sm2->getPublicKey()->encrypt('123');
        $this->assertEquals($sm2->decrypt($encrypted), '123');
    }
}