<?php

namespace phpseclib3\Crypt;

use Exception;
use phpseclib3\Crypt\SM2\Curves\sm2p256v1;
use phpseclib3\Crypt\SM2\Point;
use phpseclib3\Crypt\SM3\SM3Digest;
use phpseclib3\Crypt\SM2\Formats\Signature\ASN1;
use phpseclib3\Math\BigInteger;

class SM2 {

    /**
     * 中间了椭圆固定，在加密时减少生成密码对，性能有所提升，安全性有所下降，
     * @var mixed|true
     */
    private $fixForeignKey = false;

    /**
     * true则同一字符串，同样密钥，每次签名不一样，false是每次签名都一样
     * @var false|mixed
     */
    private $randSign = true;

    protected $p;
    protected $a;
    protected $b;
    protected $n;
    protected $gx;
    protected $gy;

    protected $privateKey;

    protected bool $randEnc = true;  // true则同一字符串，同样密钥，每次加密不一样，false是每次加密都一样

    //请自行重新生成一对，示例中的foreignKey可能被大量项目使用，而被对方加黑
    protected array $foreignKey = [
        '21fbd478026e2d668e3570e514de0d312e443d1e294c1ca785dfbfb5f74de225',
        '04e27c3780e7069bda7082a23a489d77587ce309583ed99253f66e1d9833ed1a1d0b5ce86dc6714e9974cf258589139d7b1855e8c9fa2f2c1175ee123a95a23e9b'
    ];
    private sm2p256v1 $curve;

    function __construct()
    {
        $this->curve = new sm2p256v1();
        $eccParams = $this->curve->getParams();
        $this->p = $eccParams['p'];
        $this->a = $eccParams['a'];
        $this->b = $eccParams['b'];
        $this->n = $eccParams['n'];
        // 计算基点G
        $this->gx = $eccParams['gx'];
        $this->gy = $eccParams['gy'];
    }

    public function mod(BigInteger $a, BigInteger $b): BigInteger
    {
        return new BigInteger(intval($a->toString()) % intval($b->toString()));
    }

    public function generalPair(): array
    {
        $pointG = new Point($this->gx, $this->gy);
        $prikeyGmp = $this->randPrikey();
        $publicKey = $this->getPkeyFromPrikey($prikeyGmp, $pointG);
        $prikey = $this->decHex($prikeyGmp, 64);
        return [$prikey, $publicKey];
    }

    /**
     * 通过私钥算公钥  Pub = pG
     *
     * @param BigInteger $prikeyGmp
     * @param null $pointG
     * @return string
     * @throws Exception
     */
    public function getPkeyFromPrikey(BigInteger $prikeyGmp, $pointG = null): string
    {
        if (empty($pointG)) {
            $pointG = new Point($this->gx, $this->gy);
        }
        $kG = $pointG->mul($prikeyGmp, false);
        $x1 = $this->decHex($kG->getX(), 64);
        $y1 = $this->decHex($kG->getY(), 64);
        return '04' . $x1 . $y1;
    }

    // 生成标准的 base64 的 asn1(r,s)签名
    public function sign($document, $prikey, $publicKey = null, $userId = null): string
    {
        list($r, $s) = $this->signRaw($document, $prikey, $publicKey, $userId);
        return Asn1::rsToAsn1($r, $s);
    }

    /**
     * @param string $document
     * @param string $prikey
     * @param null $publicKey //这个值虽然可以从prikey中计算出来，但直接给出来，不用每次计算，性能会好一点点
     * @param null $userId
     * @return array
     * @throws Exception
     */
    public function signRaw($document, $prikey, $publicKey = null, $userId = null): array
    {
        $gmpPrikey = new BigInteger($prikey, 16);
        // 如果知道公钥直接填上是好的，减少运算，虽说从私钥可以算出公钥，这不浪费资源不是
        if (empty($publicKey)) {
            $publicKey = $this->getPkeyFromPrikey($gmpPrikey);
        }

        $hash = $this->getSm2withSm3Hash($document, $publicKey, $userId);
        $gmpHash = new BigInteger($hash, 16);

        $count = 0;
        while (true) {
            $count++;
            if ($count > 5) {
                //5次都有问题，肯定有问题了
                throw new Exception('Error: sign R or S = 0');
            }
            //中间椭圆的私钥
            // $k = gmp_init('21fbd478026e2d668e3570e514de0d312e443d1e294c1ca785dfbfb5f74de225',16);
            $k = $this->_getForeignPrikey($document);
            // var_dump(gmp_strval($k,16),'21fbd478026e2d668e3570e514de0d312e443d1e294c1ca785dfbfb5f74de225');
            $gmpP1x = $this->_getForeignPubKeyX($k);
            $r = $this->mod($gmpHash->add($gmpP1x), $this->n);
            $zero = new BigInteger(0);
            if ($r->compare($zero) === 0) {
                continue; //报错重来一次
            }

            $one = new BigInteger(1);
            $s1 = new BigInteger(gmp_invert($one->add($gmpPrikey), $this->n));
            $s2 = $k->subtract($r->multiply( $gmpPrikey));
            $s = $this->mod($s1->multiply($s2), $this->n);

            if ($s->compare($zero) === 0) {
                continue;
                // throw new \RuntimeException('Error: random number S = 0');
            }
            return [new BigInteger($r, 16), new BigInteger($s, 16)];
        }
    }

    // 标准的asn1 base64签名验签
    public function verify($document, $publicKey, $sign, $userId = null): bool
    {
        list($hexR, $hexS) = ASN1::class::asn1ToRs($sign);
        return $this->veriftySignRaw($document, $publicKey, $hexR, $hexS, $userId);
    }


    /**
     * Undocumented function
     *
     * @param string $document bin
     * @param string $publicKey hex
     * @param string $hexR hex
     * @param string $hexS hex
     * @param null $userId
     * @return bool
     * @throws Exception
     */
    public function veriftySignRaw($document, $publicKey, $hexR, $hexS, $userId = null): bool
    {
        $plen = strlen($publicKey);
        if ($plen == 130 && substr($publicKey, 0, 2) == '04') {
            $pubX = substr($publicKey, 2, 64);
            $pubY = substr($publicKey, -64);
        } else if ($plen == 128) {
            $pubX = substr($publicKey, 0, 64);
            $pubY = substr($publicKey, -64);
        } else {
            throw new Exception("bad publicKey $publicKey");
        }
        // 1.2.3.4 sm3 取msg,userid的 hash值,
        $hash = new BigInteger($this->getSm2withSm3Hash($document, $publicKey, $userId), 16);

        $r = new BigInteger($hexR, 16);
        $s = new BigInteger($hexS, 16);
        $n = $this->n;

        $one = new BigInteger(1);
        if ($r->compare($one) < 0 || $r->compare($n->subtract($one)) > 0) {
            return false;
        }

        if ($s->compare($one) < 0 || $s->compare($n->subtract($one)) > 0) {
            return false;
        }

        // 第五步 计算t=(r'+s')mod n
        $t = $this->mod($r->add($s), $n);
        // // 第六步 计算(x1,y1) = [s]G + [t]P
        $pointG = new Point($this->gx, $this->gy); //生成基准点
        $p1 = $pointG->mul($s, false); // p1 = sG
        $pointPub = new Point(new BigInteger($pubX, 16), new BigInteger($pubY, 16)); //生成公钥的基准点
        $p2 = $pointPub->mul($t, false); // p2 = tP
        $xy = $p1->add($p2);
        // // 第七步 vR=(hash' + x1')
        $v = $this->mod($hash->add($xy->getX()), $n);

        // 最后结果 比较 $v和$r是否一致
        // var_dump(gmp_strval($v,16),$hexR);
        return new BigInteger($v, 16) == $hexR;
    }

    /**
     *
     * @param string $publicKey hex
     * @param string $data bin
     * @param string $model
     * @return string hex
     * @throws Exception
     */
    public function encrypt($publicKey, $data, string $model = 'C1C3C2'): string
    {
        list($c1, $c3, $c2) = $this->encryptRaw($publicKey, $data);
        if ($model == 'C1C3C2') {
            return $c1 . $c3 . $c2;
        } else if ($model == 'C1C2C3') {
            return $c1 . $c2 . $c3;
        }
        return $c1 . $c3 . $c2;
    }

    /**
     *
     * @param string $publicKey hex
     * @param string $data bin
     * @return array <string>
     * @throws Exception
     */
    public function encryptRaw($publicKey, $data): array
    {
        list($pubX, $pubY) = $this->_getPubXy($publicKey);
        $point = new Point($pubX, $pubY);
        $t = '';
        $count = 0;
        while (!$t) {
            $count++;
            if ($count > 5) {
                throw new Exception('bad kdf '); // 这处一般是生成的$k问题，5次都有问题，这运气差的可以买双色球了
            }

            if ($this->fixForeignKey) { //使用固定的第中间椭圆
                list($x1, $y1) = $this->_getPubXy($this->foreignKey[1], false);
                $k = new BigInteger($this->foreignKey[0], 16);

                $x1 = $this->format_hex($x1, 64); // 不足前面补0
                $y1 = $this->format_hex($y1, 64); // 不足前面补0
            } else {
                $k = $this->_getForeignPrikey($data . '_' . $count);
                //dump($k);
                //$k = gmp_init('104953050056413721046883757640585885959005820148174417356964987920496726278110',10);
                $kG = $point->mul($k);
                $x1 = $this->decHex($kG->getX(), 64);
                $y1 = $this->decHex($kG->getY(), 64);
            }
            $c1 = $x1 . $y1;
            $kPb = $point->mul($k, false);
            dump($kPb->getX());
            $x2 = new BigInteger($kPb->getX(), 16);
            $y2 = new BigInteger($kPb->getY(), 16);
            $x2 = pack('H*', str_pad($x2, 64, 0, STR_PAD_LEFT));
            $y2 = pack('H*', str_pad($y2, 64, 0, STR_PAD_LEFT));
            $t = $this->kdf($x2 . $y2, strlen($data));
        }
        // 如果字符太长的话，可能会消耗大量内存影响性能，换成普通的xor算法
        // $c2 = gmp_xor(gmp_init($t, 16), $this->str2gmp($data));
        // $c2 = $this->decHex($c2, strlen($data) * 2);
        $c2 = $this->_xor(hex2bin($t),$data);
        $c3 = $this->hashSm3($x2 . $data . $y2);
        return array($c1, $c3, $c2);
    }

    protected function _xor($str1,$str2): string
    {
        $length = strlen($str1);
        $result = array();
        for ($i = 0; $i < $length; $i++) {
            $result []= chr(ord($str1[$i]) ^ ord($str2[$i]));
        }
        return bin2hex(implode('',$result));
    }

    /**
     *
     * @param string $prikey hex
     * @param string $encryptData
     * @param string $model
     * @param boolean $trim
     * @return string
     * @throws Exception
     */
    public function decrypt($prikey, $encryptData, $model = 'C1C3C2', $trim = true)
    {
        if (strlen($prikey) == 66 && substr($prikey, 0, 2) == '00') {
            $prikey = substr($prikey, 2); // 个别的key 前面带着00
        }
        list($c1, $c3, $c2) = $this->_getC123($encryptData, $model, $trim);
        return $this->decryptRaw($prikey, $c1, $c3, $c2);
    }

    /**
     * sm2非对称解密
     *
     * @param string $prikey 私钥明文 hex len: 64
     * @param string $c1 hex
     * @param string $c3 hex
     * @param string $c2 hex
     * @return string  decode($c2) 解密结果
     * @throws Exception
     */
    public function decryptRaw(string $prikey, string $c1, string $c3, string $c2): string
    {
        list($x1, $y1) = $this->_getPubXy($c1);
        $point = new Point($x1, $y1);
        $dbC1 = $point->mul(new BigInteger($prikey, 16), false);
        $x2 = new BigInteger($dbC1->getX(), 16);
        $y2 = new BigInteger($dbC1->getY(), 16);
        $x2 = pack('H*', str_pad($x2, 64, 0, STR_PAD_LEFT));
        $y2 = pack('H*', str_pad($y2, 64, 0, STR_PAD_LEFT));
        $len = strlen($c2);
        $t = $this->kdf($x2 . $y2, $len / 2);  // 转成16进制后 字符长度要除以2
        // $m1 = gmp_strval(gmp_xor(gmp_init($t, 16), gmp_init($c2, 16)), 16);

        $m1 = $this->_xor(hex2bin($t),hex2bin($c2));
        $m1 = pack("H*", $m1);
        $u = $this->hashSm3($x2 . $m1 . $y2);

        if (strtoupper($u) != strtoupper($c3)) {
            throw new Exception("error decrypt data");
        }

        return $m1;
    }

    protected function kdf($z, $klen): string
    {
        $res = '';
        $ct = 1;
        $j = ceil($klen / 32);
        for ($i = 0; $i < $j; $i++) {
            // $ctStr = str_pad(chr($ct), 4, chr(0), STR_PAD_LEFT); //这个256个块以内是正确的，多的后就不正确了
            $hexCt = dechex($ct);
            $ctStr = hex2bin(str_pad($hexCt, 8, '0', STR_PAD_LEFT));
            $hex = $this->hashSm3($z . $ctStr);
            if ($i + 1 == $j && $klen % 32 != 0) {  // 最后一个 且 $klen/$v 不是整数
                $res .= substr($hex, 0, ($klen % 32) * 2); // 16进制比byte长度少一半 要乘2
            } else {
                $res .= $hex;
            }
            $ct++;
        }
        // var_dump($res);die();
        return $res;
    }

    /**
     *
     * @param string $message
     * @param boolean $raw
     * @return string
     */
    public function hashSm3($message, $raw = false): string
    {
        return $raw? (new BigInteger(SM3Digest::hash($message), 16))->toString():SM3Digest::hash($message);
    }

    /**
     * hex 用0补齐一定的位置
     *
     * @param string $hex
     * @param integer $count
     * @return string
     */
    public function format_hex(string $hex, int $count = 64): string
    {
        return str_pad($hex, $count, "0", STR_PAD_LEFT);
    }

    /**
     * 采用gmp自带的函数随机生成私钥，gmp_random_bits需要5.6.3才有
     * 也可其他随机函数生成
     *
     * @param integer $numBits
     * @return BigInteger
     * @throws Exception
     */
    public function randPrikey(int $numBits = 256): BigInteger
    {
        if (!function_exists('gmp_random_bits')) {
            return $this->_getForeignPrikey('loveyou' . microtime());
        }
        $value = BigInteger::random($numBits);
        $mask = (new BigInteger($numBits))->pow(new BigInteger(2))->subtract(new BigInteger(1));
        return $value->bitwise_and($mask);
    }

    /**
     * gmp 转 hex,并用0补齐位数
     *
     * @param BigInteger|int $dec
     * @param integer $len
     * @return string
     * @throws Exception
     */
    public function decHex($dec, int $len = 0): string
    {
        if (!$dec instanceof BigInteger) {
            $dec = new BigInteger($dec);
        }
        if ($dec->compare(new BigInteger(0)) < 0) {
            throw new Exception('Unable to convert negative integer to string');
        }

        $hex = $dec->toHex();

        if (strlen($hex) % 2 != 0) {
            $hex = '0' . $hex;
        }
        if ($len && strlen($hex) < $len) {  // point x y 要补齐 64 位
            $hex = str_pad($hex, $len, "0", STR_PAD_LEFT);
        }
        return $hex;
    }

    /**
     * 生成随机私钥
     *
     * @param string $document
     * @return BigInteger
     * @throws Exception
     */
    protected function _getForeignPrikey($document = ''): BigInteger
    {
        // 要支持php5的话，没有什么好函数了，如果是php7或以上或以使用
        // $s = random_bytes(64) 或  this->rand_prikey(int bits=256)  代替
        // 如个人使用，请更新为自己相应的盐值
        $s1 = 'S1';
        $s2 = 'S2';
        if ($this->randSign || $this->randEnc) { // 从document ==>k 变化
            $s = substr(openssl_digest($s1 . $document . microtime(), 'sha1'), 1, 32) . md5($document . microtime() . $s2);
        } else {
            $s = substr(openssl_digest($s1 . $document, 'sha1'), 1, 32) . md5($document . $s2);
        }

        $s = strtolower($s);
        if (substr($s, 0, 1) == 'f') { //私钥不要太大了，超过 n值就不好了，
            $s = 'e' . substr($s, 1);
        }
        return new BigInteger($s, 16);
    }

    /**
     *
     * @param string $document
     * @param string $publicKey
     * @param string $userId
     * @return string
     * @throws Exception
     */
    public function getSm2withSm3Hash($document, $publicKey, $userId): string
    {
        //  置M’=ZA∥M；ZA= Hv(ENTLA||IDA||a||b||Gx||Gy||Ax||Ay)； IDA==>userId
        // ENTLA为IDA的比特长度，2字节；IDA用户标识默认值见上节；a,b,Gx,Gy见曲线参数；Ax,Ay为公钥坐标
        $len = strlen($publicKey);
        if ($len == 130) {
            $publicKey = substr($publicKey, 2);
        } else if ($len != 128) {
            throw new Exception('bad publicKey');
        }
        $px = new BigInteger(substr($publicKey, 0, 64), 16);
        $py = new BigInteger(substr($publicKey, 64, 64), 16);
        $zStr = $this->_getEntla($userId);
        $zStr .= $userId;
        $zStr .= $this->a->toBits();
        $zStr .= $this->b->toBits();
        $zStr .= $this->gx->toBits();
        $zStr .= $this->gy->toBits();
        $zStr .= $px->toBits();
        $zStr .= $py->toBits();
        $hashStr = $this->hashSm3($zStr);
        return $this->hashSm3(hex2bin($hashStr) . $document);
    }

    protected function _getForeignPubKeyX($k): BigInteger
    {
        $pointG = new Point($this->gx, $this->gy);
        $kG = $pointG->mul($k, false);
        return $kG->getX();
    }

    protected function _getEntla($userId): string
    {
        $len = strlen($userId) * 8;
        $l1 = $len >> 8 & 0x00ff;
        $l2 = $len & 0x00ff;
        return chr($l1) . chr($l2);
    }

    protected function _gmpToBin(BigInteger $gmp): string
    {
        return $gmp->toHex();
    }

    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function setRandSignFlag($flag = false)
    {
        $this->randSign = $flag;
    }

    public function setRandEncFlag($flag = false)
    {
        $this->randEnc = $flag;
    }

    public function setFixForeignKeyFlag($flag = true)
    {
        $this->fixForeignKey = $flag;
    }
    
    public function str2gmp($string): BigInteger
    {
        $hex = unpack('H*', $string);

        return new BigInteger($hex[1], 16);
    }

    protected function _getPubXy($publicKey, $rtGmp = true): array
    {
        $pLen = strlen($publicKey);
        if ($pLen == 130 && substr($publicKey, 0, 2) == '04') {
            $pubX = substr($publicKey, 2, 64);
            $pubY = substr($publicKey, -64);
        } else if ($pLen == 128) {
            $pubX = substr($publicKey, 0, 64);
            $pubY = substr($publicKey, -64);
        } else {
            throw new Exception("bad publicKey $publicKey");
        }
        if ($rtGmp) {
            return array(new BigInteger($pubX, 16), new BigInteger($pubY, 16));
        }
        return array($pubX, $pubY);
    }

    protected function _getC123($encryptData, $model = 'C1C3C2', $trim = true): array
    {
        if (substr($encryptData, 0, 2) == '04' && $trim) {
            $encryptData = substr($encryptData, 2);
        }
        $c1Length = 128;
        $c1 = substr($encryptData, 0, $c1Length);
        if ($model == 'C1C3C2') {
            $c3 = substr($encryptData, $c1Length, 64);
            $c2 = substr($encryptData, $c1Length + strlen($c3));
        } else {
            $c3 = substr($encryptData, -64);
            $c2 = substr($encryptData, $c1Length, -64);
        }
        return array($c1, $c3, $c2);
    }
}