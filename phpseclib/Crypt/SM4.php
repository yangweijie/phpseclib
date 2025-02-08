<?php

declare(strict_types=1);

namespace phpseclib3\Crypt;

use Exception;
use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadModeException;
use phpseclib3\Exception\InvalidArgumentException;

class SM4 extends BlockCipher
{
    /**
     * Mode Map
     *
     * @see \phpseclib3\Crypt\Common\SymmetricKey::__construct()
     */
    public const MODE_MAP = [
        'ctr'    => self::MODE_CTR,
        'ecb'    => self::MODE_ECB,
        'cbc'    => self::MODE_CBC,
        'cfb'    => self::MODE_CFB,
        'ofb'    => self::MODE_OFB,
    ];

    /**
     * Engine Reverse Map
     *
     * @see \phpseclib3\Crypt\Common\SymmetricKey::getEngine()
     */
    public const ENGINE_MAP = [
        self::ENGINE_EVAL        => 'Eval',
        self::ENGINE_OPENSSL     => 'OpenSSL',
    ];


    /**
     * The Encryption Mode
     *
     * @see self::__construct()
     * @var int
     */
    protected $mode;

    /**
     * Holds which crypt engine internaly should be use,
     * which will be determined automatically on __construct()
     *
     * Currently available $engines are:
     * - self::ENGINE_LIBSODIUM   (very fast, php-extension: libsodium, extension_loaded('libsodium') required)
     * - self::ENGINE_OPENSSL_GCM (very fast, php-extension: openssl, extension_loaded('openssl') required)
     * - self::ENGINE_OPENSSL     (very fast, php-extension: openssl, extension_loaded('openssl') required)
     * - self::ENGINE_EVAL        (medium, pure php-engine, no php-extension required)
     * - self::ENGINE_INTERNAL    (slower, pure php-engine, no php-extension required)
     *
     * @see self::setEngine()
     * @see self::encrypt()
     * @see self::decrypt()
     * @var int
     */
    protected $engine;

    /**
     * The Block Length of the block cipher
     *
     * @var int
     */
    protected $block_size = 16;

    /**
     * The Key
     *
     * @see self::setKey()
     * @var string
     */
    protected $key = false;


    /**
     * The Initialization Vector
     *
     * @see self::setIV()
     * @var string
     */
    protected $iv = false;

    /**
     * The Key Length (in bytes)
     *
     * {@internal The max value is 256 / 8 = 32, the min value is 128 / 8 = 16.  Exists in conjunction with $Nk
     *    because the encryption / decryption / key schedule creation requires this number and not $key_length.  We could
     *    derive this from $key_length or vice versa, but that'd mean we'd have to do multiple shift operations, so in lieu
     *    of that, we'll just precompute it once.}
     *
     * @see self::setKeyLength()
     * @var int
     */
    protected $key_length = 16;

    private string $origIV;

    private array $rk;

    /**
     * 构造函数
     *
     * @param string      $key  必须为16字节
     * @param string      $mode 支持：cbc|ecb|ofb|cfb|ctr（不区分大小写）
     * @param string|null $iv   除 ecb 模式外必须提供16字节IV
     *
     * @throws Exception
     */
    public function __construct(string $key, string $mode = 'cbc', ?string $iv = null)
    {
        if (strlen($key) !== 16) {
            throw new Exception("SM4 密钥必须为16字节");
        }
        $this->key = $key;
        $mode = strtolower($mode);
        $supported_modes = ['cbc', 'ecb', 'ofb', 'cfb', 'ctr'];
        if (!in_array($mode, $supported_modes, true)) {
            throw new Exception("不支持的模式：{$mode}，只支持 " . implode(', ', $supported_modes));
        }
        parent::__construct($mode);
        $this->mode = self::MODE_MAP[$mode];
        if ($mode !== 'ecb') {
            $this->setIV($iv);
        }
        $this->setEngine();
        $this->setupInlineCrypt();
    }


    /**
     * 加密数据并返回原始二进制密文 实现 CBC|ECB|OFB|CFB|CTR 模式
     *
     * @param string $plaintext
     * @return string
     * @throws Exception
     */
    public function encrypt(string $plaintext): string
    {
        if($this->getEngine() == self::ENGINE_MAP[self::ENGINE_OPENSSL]){
            return parent::encrypt($plaintext);
        }
        $plaintext = self::pkcs7Pad($plaintext, 16);
        $blocks = str_split($plaintext, 16);
        $result = '';

        switch (array_search($this->mode, self::MODE_MAP)) {
            case 'ecb':
                foreach ($blocks as $block) {
                    $result .= $this->encryptBlock($block);
                }
                break;
            case 'cbc':
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $block = $this->strXOR($block, $prev);
                    $encrypted = $this->encryptBlock($block);
                    $result .= $encrypted;
                    $prev = $encrypted;
                }
                break;
            case 'ofb':
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $prev = $this->encryptBlock($prev);
                    $result .= $this->strXOR($block, $prev);
                }
                break;
            case 'cfb':
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $cipherOut = $this->encryptBlock($prev);
                    $encrypted = $this->strXOR($block, $cipherOut);
                    $result .= $encrypted;
                    $prev = $encrypted;
                }
                break;
            case 'ctr':
                $counter = $this->iv;
                foreach ($blocks as $block) {
                    $keystream = $this->encryptBlock($counter);
                    $result .= $this->strXOR($block, $keystream);
                    $counter = self::incCounter($counter);
                }
                break;
            default:
                throw new Exception("未知模式：{$this->mode}");
        }
        return $result;
    }

    /**
     * 解密原始二进制密文并返回明文
     *
     * @param string $ciphertext
     * @return string
     * @throws Exception
     */
    public function decrypt(string $ciphertext): string
    {
        if($this->getEngine() == self::ENGINE_MAP[self::ENGINE_OPENSSL]){
            return parent::decrypt($ciphertext);
        }
        $blocks = str_split($ciphertext, 16);
        $result = '';

        switch (array_search($this->mode, self::MODE_MAP)) {
            case 'ecb':
                foreach ($blocks as $block) {
                    $result .= $this->decryptBlock($block);
                }
                break;
            case 'cbc': {
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $decrypted = $this->decryptBlock($block);
                    $result .= $this->strXOR($decrypted, $prev);
                    $prev = $block;
                }
                break;
            }
            case 'ofb': {
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $prev = $this->encryptBlock($prev);
                    $result .= $this->strXOR($block, $prev);
                }
                break;
            }
            case 'cfb': {
                $prev = $this->iv;
                foreach ($blocks as $block) {
                    $cipherOut = $this->encryptBlock($prev);
                    $result .= $this->strXOR($block, $cipherOut);
                    $prev = $block;
                }
                break;
            }
            case 'ctr': {
                $counter = $this->iv;
                foreach ($blocks as $block) {
                    $keystream = $this->encryptBlock($counter);
                    $result .= $this->strXOR($block, $keystream);
                    $counter = self::incCounter($counter);
                }
                break;
            }
            default:
                throw new Exception("未知模式：{$this->mode}");
        }
        return self::pkcs7Unpad($result);
    }

    // ------------------------ fallback（ENGINE_EVAL）实现 ------------------------

    protected static function pkcs7Pad(string $data, int $block_size = 16): string
    {
        $pad = $block_size - (strlen($data) % $block_size);
        return $data . str_repeat(chr($pad), $pad);
    }

    protected static function pkcs7Unpad(string $data): string
    {
        $pad = ord(substr($data, -1));
        return substr($data, 0, -$pad);
    }

    // 辅助：字符串异或运算，要求两个字符串长度一致
    protected function strXOR(string $a, string $b): string
    {
        $result = '';
        for ($i = 0, $len = strlen($a); $i < $len; $i++) {
            $result .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        return $result;
    }

    // 辅助：CTR 模式中计数器大端自增1（16字节整数）
    protected static function incCounter(string $counter): string
    {
        $num = gmp_init(bin2hex($counter), 16);
        $num = gmp_add($num, 1);
        $hex = gmp_strval($num, 16);
        $hex = str_pad($hex, 32, '0', STR_PAD_LEFT);
        return pack("H*", $hex);
    }

    // -------------------- SM4 纯 PHP 核心部分 --------------------

    // S-Box 表
    protected static $Sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ];

    // FK 常量
    protected static $FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

    // CK 常量
    protected static $CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ];

    /**
     * Test for engine validity
     *
     * This is mainly just a wrapper to set things up for \phpseclib3\Crypt\Common\SymmetricKey::isValidEngine()
     *
     * @see \phpseclib3\Crypt\Common\SymmetricKey::__construct()
     */
    protected function isValidEngineHelper(int $engine): bool
    {
        switch ($engine) {
            case self::ENGINE_OPENSSL:
                if ($this->block_size != 16) {
                    return false;
                }
                $this->cipher_name_openssl_ecb = 'sm4-ecb';
                $this->cipher_name_openssl = 'sm4-' . $this->openssl_translate_mode();
                break;
        }

        return parent::isValidEngineHelper($engine);
    }

    protected function setupInlineCrypt(): void
    {
        $this->rk = self::fallbackGenerateRoundKeys($this->key);
    }

    // 生成32轮密钥数组，传入 16 字节密钥，输出32个32位整数
    protected static function fallbackGenerateRoundKeys(string $key): array
    {
        // 拆分密钥为4个32位整数
        $key_arr = array_values(unpack("N4", $key));
        $K = [];
        for ($i = 0; $i < 4; $i++) {
            $K[$i] = $key_arr[$i] ^ self::$FK[$i];
        }
        $rk = [];
        for ($i = 0; $i < 32; $i++) {
            $temp = $K[$i+1] ^ $K[$i+2] ^ $K[$i+3] ^ self::$CK[$i];
            $temp = self::tau($temp);
            $temp = self::L_prime($temp);
            $K[$i+4] = $K[$i] ^ $temp;
            $rk[$i] = $K[$i+4];
        }
        return $rk;
    }

    // 非线性变换 tau: 对 32 位整数按字节分解，代入 S-Box
    protected static function tau(int $A): int
    {
        $a0 = ($A >> 24) & 0xFF;
        $a1 = ($A >> 16) & 0xFF;
        $a2 = ($A >> 8) & 0xFF;
        $a3 = $A & 0xFF;
        $b0 = self::$Sbox[$a0];
        $b1 = self::$Sbox[$a1];
        $b2 = self::$Sbox[$a2];
        $b3 = self::$Sbox[$a3];
        return (($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3) & 0xFFFFFFFF;
    }

    // 线性变换 L' 用于密钥扩展
    protected static function L_prime(int $B): int
    {
        return $B ^ self::rotl32($B, 13) ^ self::rotl32($B, 23);
    }

    // 对于加解密轮，线性变换 L
    protected static function L(int $B): int
    {
        return $B ^ self::rotl32($B, 2) ^ self::rotl32($B, 10) ^ self::rotl32($B, 18) ^ self::rotl32($B, 24);
    }

    // 32位循环左移
    protected static function rotl32(int $x, int $n): int
    {
        return ((($x << $n) & 0xFFFFFFFF) | ($x >> (32 - $n))) & 0xFFFFFFFF;
    }

    protected function processBlock(string $in, array $roundKeys): string
    {
        $X = array_values(unpack("N4", $in));
        foreach ($roundKeys as $rk) {
            $temp = $X[1] ^ $X[2] ^ $X[3] ^ $rk;
            $temp = self::tau($temp);
            $temp = self::L($temp);
            $new = $X[0] ^ $temp;
            $X = [$X[1], $X[2], $X[3], $new];
        }
        return pack("N4", $X[3], $X[2], $X[1], $X[0]);
    }

    protected function encryptBlock(string $in): string
    {
        return $this->processBlock($in, $this->rk);
    }

    protected function decryptBlock(string $in): string
    {
        return $this->processBlock($in, array_reverse($this->rk));
    }

    protected function setupKey()
    {
    }
}