<?php

namespace phpseclib3\Tests\Unit\Crypt;

use phpseclib3\Crypt\SM3\Formats\Signature\SM3;
use phpseclib3\Tests\PhpseclibTestCase;

class SM3Test extends PhpseclibTestCase
{
    public function testSign(){
        $sm3 = new SM3('');
        $this->assertEquals($sm3->sign('abc'), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
    }
}