<?php

namespace phpseclib3\Crypt;

use Exception;
use phpseclib3\Crypt\SM2\PublicKey;
use phpseclib3\File\ASN1;

class SM2 {
    protected EC $ec;
    protected string $mode;
    protected static string $curve = 'sm2p256v1';

    public function __construct(EC $ec, string $mode = 'C1C3C2') {
        $this->ec = $ec;
        $this->mode = $mode;
    }

    public static function createKey(string $mode = 'C1C3C2'): self {
        $curve = self::$curve;
        $ec = EC::createKey($curve);
        return new self($ec, $mode);
    }

    public function getPublicKey(): PublicKey {
        return new PublicKey($this->ec->getParameters()->getPublicKey(), $this->mode);
    }

    /**
     * @throws Exception
     */
    public function decrypt(string $ciphertext): string {
        $localMode = $this->mode;
        if (strlen($ciphertext) > 0 && ord($ciphertext[0]) === 0x30) {
            $decoded = ASN1::decodeBER($ciphertext);
            if (empty($decoded)) {
                throw new Exception('ASN1 解码失败');
            }
            $structure = [
                'type'     => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'c1x' => ['type' => ASN1::TYPE_INTEGER],
                    'c1y' => ['type' => ASN1::TYPE_INTEGER],
                    'c3'  => ['type' => ASN1::TYPE_OCTET_STRING],
                    'c2'  => ['type' => ASN1::TYPE_OCTET_STRING]
                ]
            ];
            $mapped = ASN1::asn1map($decoded[0], $structure);
            if ($mapped === false) {
                throw new Exception('ASN1 映射失败');
            }
            $c1x_bin = self::intToFixedBytes($mapped['c1x']);
            $c1y_bin = self::intToFixedBytes($mapped['c1y']);
            $C1 = "\x04" . $c1x_bin . $c1y_bin;
            $C3 = $mapped['c3'];
            $C2 = $mapped['c2'];
            $ciphertext = $C1 . $C3 . $C2;
            $localMode = 'C1C3C2';
        }

        $minLen = 65 + 32;
        if (strlen($ciphertext) < $minLen) {
            throw new Exception('密文格式错误');
        }
        if ($localMode === 'C1C3C2') {
            $C1 = substr($ciphertext, 0, 65);
            $C3 = substr($ciphertext, 65, 32);
            $C2 = substr($ciphertext, 97);
        } elseif ($localMode === 'C1C2C3') {
            $C1 = substr($ciphertext, 0, 65);
            $C3 = substr($ciphertext, -32);
            $C2 = substr($ciphertext, 65, strlen($ciphertext) - 65 - 32);
        } else {
            throw new Exception('未支持的密文格式模式');
        }

        $ec_temp = EC::createKey(self::$curve);
        $publicKeyObj = $ec_temp->loadPublicKey($C1);
        // 获取底层的椭圆曲线点对象
        $C1_point = $publicKeyObj->toString('uncompressed'); // Replace with the correct method to get the point

        $privateKey = $this->ec->toString('PKCS8');
        $sharedPoint = $C1_point->getPoint()->multiply($privateKey);

        $x2 = self::fixedLength($sharedPoint->getX());
        $y2 = self::fixedLength($sharedPoint->getY());

        $keyStream = self::KDF($x2 . $y2, strlen($C2));
        if ($keyStream === str_repeat("\0", strlen($C2))) {
            throw new Exception("KDF 结果全零");
        }

        $M = $C2 ^ $keyStream;

        $C3_prime = hash('sha256', $x2 . $M . $y2, true);
        if (!hash_equals($C3, $C3_prime)) {
            throw new Exception('杂凑验证失败，密文可能被篡改');
        }

        return $M;
    }

    public static function KDF(string $Z, int $klen): string {
        $ct = 1;
        $key = '';
        while (strlen($key) < $klen) {
            $key .= hash('sha256', $Z . pack('N', $ct), true);
            $ct++;
        }
        return substr($key, 0, $klen);
    }

    public static function fixedLength($num): string {
        if (is_object($num) && method_exists($num, 'toBytes')) {
            $num = $num->toBytes();
        }
        return str_pad($num, 32, "\0", STR_PAD_LEFT);
    }

    protected static function intToFixedBytes(int $value): string {
        $g = gmp_init($value);
        $bin = gmp_export($g);
        return str_pad($bin, 32, "\0", STR_PAD_LEFT);
    }
}