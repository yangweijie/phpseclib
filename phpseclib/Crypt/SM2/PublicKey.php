<?php

namespace phpseclib3\Crypt\SM2;
use Exception;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\SM2 as SM2Base;
use phpseclib3\Math\BigInteger;

class PublicKey
{
    /**
     * @var EC 公钥对象
     */
    protected mixed $publicKey;

    /**
     * 模式，支持 "C1C3C2" 与 "C1C2C3"
     *
     * @var string
     */
    protected string $mode;

    /**
     * 构造函数
     *
     * @param mixed $publicKey
     * @param string $mode
     */
    public function __construct(mixed $publicKey, string $mode = 'C1C3C2')
    {
        $this->publicKey = $publicKey;
        $this->mode = $mode;
    }

    /**
     * 使用 SM2 公钥加密数据
     *
     * @param string $plaintext 要加密的明文
     * @return string SM2 密文，格式根据模式确定
     * @throws Exception 加密失败时抛出异常
     */
    public function encrypt(string $plaintext): string
    {
        $curve = 'sm2p256v1';

        // 1. 生成随机数 k 及临时密钥对 ephemeral
        $ec_temp = EC::createKey($curve);
        $ephemeralKey = $ec_temp;
        $C1 = $ephemeralKey->getPublicKey()->toString('uncompressed'); // 65 字节格式

        // 2. 计算共享点：P = [k] * recipientPublic，其中 k 为 ephemeralKey 的私钥
        // 将私钥转换为 BigInteger 对象：
        $k = new BigInteger($ephemeralKey->toString('dec'));
        $sharedPoint = $this->publicKey->getPoint()->multiply($k); // 先获取公钥的点对象再调用乘法

        // 3. 转换共享点坐标为定长 32 字节大端格式
        $x2 = SM2Base::fixedLength($sharedPoint->getX());
        $y2 = SM2Base::fixedLength($sharedPoint->getY());

        // 4. 生成与明文长度相同的密钥流
        $keyStream = SM2Base::KDF($x2 . $y2, strlen($plaintext));
        if ($keyStream === str_repeat("\0", strlen($plaintext))) {
            throw new Exception("KDF 结果全零，重试加密");
        }

        // 5. 计算 C2 = 明文 XOR keyStream
        $C2 = $plaintext ^ $keyStream;

        // 6. 计算杂凑 C3 = hash(x2 || 明文 || y2)（本实例采用 sha256）
        $C3 = hash('sha256', $x2 . $plaintext . $y2, true);

        // 7. 根据模式拼接最终密文
        if ($this->mode === 'C1C3C2') {
            $ciphertext = $C1 . $C3 . $C2;
        } elseif ($this->mode === 'C1C2C3') {
            $ciphertext = $C1 . $C2 . $C3;
        } else {
            throw new Exception('未支持的密文格式模式');
        }
        return $ciphertext;
    }
}