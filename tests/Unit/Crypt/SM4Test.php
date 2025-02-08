<?php

namespace phpseclib3\Tests\Unit\Crypt;

use phpseclib3\Crypt\SM4;
use phpseclib3\Tests\PhpseclibTestCase;

class SM4Test extends PhpseclibTestCase
{
    public function testEncrypt(){
        $sm4 = new SM4('0123456789abcdef', 'cbc', '1234567887654321');
//        dump($sm4->getEngine());
        $data = '我爱你ILOVEYOU!';
        $ciphertext = $sm4->encrypt($data);
        $enc = bin2hex($ciphertext);
        $this->assertEquals($enc, '1e1ea8358ccf811fb9c67964b67a8e11ff2b7b0fa928fc69f70d46098a10bab7');
    }

    public function testDecrypt(){
        $sm4 = new SM4('0123456789abcdef', 'cbc', '1234567887654321');
        $data = 'abc';
        $ciphertext = $sm4->encrypt($data);
        $decode = $sm4->decrypt($ciphertext);
        $this->assertEquals($data, $decode);
    }
}