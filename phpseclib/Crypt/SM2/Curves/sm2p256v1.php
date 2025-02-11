<?php

declare(strict_types=1);

namespace phpseclib3\Crypt\SM2\Curves;

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class sm2p256v1 extends Prime
{
    public function __construct()
    {
        // SM2 椭圆曲线参数
        // p
        $this->setModulo(new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16));
        $this->setCoefficients(
            new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16), // a
            new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)  // b
        );
        $this->setBasePoint(
            new BigInteger('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16), // Gx
            new BigInteger('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)  // Gy
        );
        // n
        $this->setOrder(new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16));
    }

    public function getParams(): array
    {
        list($gx, $gy) = $this->getBasePoint();
        return [
            'p'=>gmp_init($this->getModulo()->toHex(), 16),
            'a'=>gmp_init($this->getA()->toHex(), 16),
            'b'=>gmp_init($this->getB()->toHex(), 16),
            'n'=>gmp_init($this->getOrder()->toHex(), 16),
            'gx'=>gmp_init($gx->toHex(), 16),
            'gy'=>gmp_init($gy->toHex(), 16),
            'size'=>256,
        ];
    }
}