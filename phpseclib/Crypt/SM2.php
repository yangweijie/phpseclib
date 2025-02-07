<?php

namespace phpseclib3\Crypt;

use Exception;
use phpseclib3\Crypt\SM3\Formats\Signature\SM3;
use phpseclib3\Math\BigInteger;

class SM2 {
    private $privateKey;  // 存放私钥（字符串或 BigInteger 根据需要转换）
    private $publicKey;   // 存放公钥对象
    private $curve;
    private $mode;        // 加密模式： 'C1C3C2' 或 'C1C2C3'

    private $tmpPrivateKey;

    /**
     * 构造函数，可传入私钥（用于解密/签名），默认加密模式为 C1C3C2
     */
    public function __construct($privateKey = null, $mode = 'C1C3C2') {
        $this->mode = $mode;

        if ($privateKey) {
            $this->privateKey = $privateKey;
            $this->curve = $privateKey->getCurve();
            // 假设 getPublicKeyFromPrivate 接口可用，将字符串转 BigInteger
            $this->publicKey = $this->curve->getPublicKeyFromPrivate(new BigInteger($privateKey, 10));
        }else{
            // 这里加载自定义的 SM2P256V1 曲线
            $this->tmpPrivateKey = EC::createKey('sm2p256v1');
            $this->publicKey = $this->tmpPrivateKey->getPublicKey();
            $this->curve = $this->tmpPrivateKey->getCurve();
        }
    }

    /**
     * 生成 SM2 密钥对
     */
    public function generateKeys() {
        $key = $this->tmpPrivateKey;
        $this->privateKey = $key->toString('PKCS1');
        $this->publicKey = $key->getPublicKey();
        return ['private' => $this->privateKey, 'public' => $this->publicKey];
    }

    public function sm3Hash($message){
        static $sm3;
        if(!isset($sm3)){
            $sm3 = new SM3('');
        }
        return $sm3->sign($message);
    }

    /**
     * SM2 加密
     * @param string $plainText 明文数据
     * @param object $recipientPublicKey 接收方公钥对象
     * @return string 拼接后的密文
     * @throws Exception
     */
    public function encrypt($plainText, $recipientPublicKey = '') {
        // 1. 随机生成临时密钥 k
        $kObj = EC::createKey($this->curve);
        $k = $kObj->toString('PKCS1');
        $C1 = $kObj->getPublicKey();  // C1 点

        // 2. 计算共享点 P2 = k * RecipientPublicKey
        if(!$recipientPublicKey){
            $recipientPublicKey = $this->publicKey;
        }
        $P2 = $kObj->multiply($k);
        $P2Coordinates = $P2->getCoordinates();
        $x2 = $P2Coordinates['x'];
        $y2 = $P2Coordinates['y'];

        // 3. 使用 KDF 得到密钥字符串，与明文长度相同（此处实现见下文）
        $klen = strlen($plainText);
        $t = $this->KDF($x2, $y2, $klen);
        if ($t === str_repeat("\0", $klen)) {
            throw new Exception("KDF 得到全 0 密钥，需重试");
        }

        // 4. 计算 C2 = 明文 XOR t
        $C2 = $this->strXOR($plainText, $t);

        // 5. 计算 C3 = SM3( x2 || M || y2 )
        $x2hex = str_pad($x2->toHex(), 64, '0', STR_PAD_LEFT);
        $y2hex = str_pad($y2->toHex(), 64, '0', STR_PAD_LEFT);
        $c3_input = pack("H*", $x2hex) . $plainText . pack("H*", $y2hex);
        $C3 = $this->sm3Hash($c3_input);

        // 6. 拼接密文，依据模式选择拼接顺序
        // 此处假设 C1->toString() 返回点的标准编码字符串（例如 uncompressed 格式）
        $C1_str = $C1->toString();
        if ($this->mode === 'C1C3C2') {
            return $C1_str . $C3 . $C2;
        } else {  // C1C2C3
            return $C1_str . $C2 . $C3;
        }
    }

    /**
     * SM2 解密
     * @param string $cipherText 拼接密文
     * @param bool $trim 是否trim C1的04
     * @return string 解密后的明文
     * @throws Exception
     */
    public function decrypt($cipherText, $trim = false) {
        // 解析 C1, C3, C2 的长度。
        // 假设 C1 为 uncompressed 点编码，固定长度 65 字节，C3 固定 32 字节，其余部分视为 C2
        $pointLength = 65;  // 可根据实际情况调整
        if (substr($cipherText, 0, 2) == '04' && $trim) {
            $cipherText = substr($cipherText, 2);
        }
        if (strlen($this->privateKey) == 66 && substr($this->privateKey, 0, 2) == '00') {
            $this->privateKey = substr($this->privateKey, 2); // 个别的key 前面带着00
        }
        $C1_str = substr($cipherText, 0, $pointLength);
        if ($this->mode === 'C1C3C2') {
            $C3 = substr($cipherText, $pointLength, 32);
            $C2 = substr($cipherText, $pointLength + 32);
        } else { // C1C2C3
            $C2 = substr($cipherText, $pointLength, strlen($cipherText) - $pointLength - 32);
            $C3 = substr($cipherText, -32);
        }

        // 还原 C1 点（假设 convert 方法可以将编码字符串转换为点对象）
        $C1 = $this->curve->convert($C1_str);

        // 计算共享点 P2 = d * C1
        $P2 = $C1->multiply(new BigInteger($this->privateKey, 10));
        $P2Coordinates = $P2->getCoordinates();
        $x2 = $P2Coordinates['x'];
        $y2 = $P2Coordinates['y'];

        // 同样利用 KDF 从 (x2,y2) 得到密钥 t，长度 = |C2|
        $klen = strlen($C2);
        $t = $this->KDF($x2, $y2, $klen);
        if ($t === str_repeat("\0", $klen)) {
            throw new Exception("KDF 得到全 0 密钥，无法解密");
        }
        // 恢复明文： M = C2 XOR t
        $M = $this->strXOR($C2, $t);

        // 验证 C3：计算 u = SM3( x2 || M || y2 ) 并比较
        $x2hex = str_pad($x2->toHex(), 64, '0', STR_PAD_LEFT);
        $y2hex = str_pad($y2->toHex(), 64, '0', STR_PAD_LEFT);
        $c3_input = pack("H*", $x2hex) . $M . pack("H*", $y2hex);
        $u = $this->sm3Hash($c3_input);
        if (strcasecmp($u, $C3) !== 0) {
            throw new Exception("解密失败：C3 校验不通过");
        }
        return $M;
    }

    /**
     * 简单实现 SM2 中的 KDF 函数，基于 SM3 哈希
     * KDF(Klen = klen)，将 x2||y2 和计数器 CT 连续哈希，直至输出长度达到 klen
     */
    private function KDF($x, $y, $klen) {
        $ct = 1;
        $key = "";
        $xHex = str_pad($x->toHex(), 64, '0', STR_PAD_LEFT);
        $yHex = str_pad($y->toHex(), 64, '0', STR_PAD_LEFT);
        while (strlen($key) < $klen) {
            $data = pack("H*", $xHex . $yHex) . pack("N", $ct);
            $key .= pack("H*", $this->sm3Hash($data));
            $ct++;
        }
        return substr($key, 0, $klen);
    }

    /**
     * 简单字符串异或操作
     */
    private function strXOR($str1, $str2) {
        $res = '';
        $len = strlen($str1);
        for ($i = 0; $i < $len; $i++) {
            $res .= $str1[$i] ^ $str2[$i];
        }
        return $res;
    }
}