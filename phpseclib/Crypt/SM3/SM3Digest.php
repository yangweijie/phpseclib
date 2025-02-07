<?php

namespace phpseclib3\Crypt\SM3;

class SM3Digest
{
    // 左循环移位
    private static function leftRotate($x, $n) {
        return (($x << $n) & 0xFFFFFFFF) | ($x >> (32 - $n));
    }

    // 布尔函数：j在[0,15]时使用异或，否则采用其它计算
    private static function FF($x, $y, $z, $j) {
        return ($j < 16) ? ($x ^ $y ^ $z) : (($x & $y) | ($x & $z) | ($y & $z));
    }
    private static function GG($x, $y, $z, $j) {
        return ($j < 16) ? ($x ^ $y ^ $z) : (($x & $y) | ((~$x) & $z));
    }

    // 置换函数
    private static function P0($x) {
        return $x ^ self::leftRotate($x, 9) ^ self::leftRotate($x, 17);
    }
    private static function P1($x) {
        return $x ^ self::leftRotate($x, 15) ^ self::leftRotate($x, 23);
    }

    public static function hash($data) {
        // 初始化IV（8个32位整数）
        $iv = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ];

        // 消息预处理：填充
        $dataLen = strlen($data);
        $bitLen = $dataLen * 8;
        $data .= chr(0x80); // 追加 1 位（10000000）
        // 追加 0 直到字节数 mod 64 == 56
        while ((strlen($data) % 64) !== 56) {
            $data .= chr(0x00);
        }
        // 追加消息原始长度（64位大端序）
        $data .= pack('N2', ($bitLen >> 32) & 0xFFFFFFFF, $bitLen & 0xFFFFFFFF);

        // 分组处理，每组64字节（512位）
        $blocks = str_split($data, 64);
        foreach ($blocks as $block) {
            $W = [];
            $W1 = [];
            // 将块拆分成 16 个 32 位整数（大端序）
            for ($i = 0; $i < 16; $i++) {
                $W[$i] = current(unpack('N', substr($block, $i * 4, 4)));
            }
            // 消息扩展
            for ($i = 16; $i < 68; $i++) {
                $tmp = $W[$i - 16] ^ $W[$i - 9] ^ self::leftRotate($W[$i - 3], 15);
                $W[$i] = self::P1($tmp) ^ self::leftRotate($W[$i - 13], 7) ^ $W[$i - 6];
            }
            for ($i = 0; $i < 64; $i++) {
                $W1[$i] = $W[$i] ^ $W[$i + 4];
            }

            // 初始状态赋值
            list($a, $b, $c, $d, $e, $f, $g, $h) = $iv;

            // 压缩函数 64 轮
            for ($j = 0; $j < 64; $j++) {
                // T 常量：前16轮为0x79cc4519，后48轮为0x7a879d8a
                $T = ($j < 16) ? 0x79cc4519 : 0x7a879d8a;
                $SS1 = self::leftRotate(((self::leftRotate($a, 12) + $e + self::leftRotate($T, $j % 32)) & 0xFFFFFFFF), 7);
                $SS2 = $SS1 ^ self::leftRotate($a, 12);
                $TT1 = (self::FF($a, $b, $c, $j) + $d + $SS2 + $W1[$j]) & 0xFFFFFFFF;
                $TT2 = (self::GG($e, $f, $g, $j) + $h + $SS1 + $W[$j]) & 0xFFFFFFFF;
                // 状态更新
                $d = $c;
                $c = self::leftRotate($b, 9);
                $b = $a;
                $a = $TT1;
                $h = $g;
                $g = self::leftRotate($f, 19);
                $f = $e;
                $e = self::P0($TT2);
            }

            // 更新IV
            $iv[0] ^= $a; $iv[1] ^= $b; $iv[2] ^= $c; $iv[3] ^= $d;
            $iv[4] ^= $e; $iv[5] ^= $f; $iv[6] ^= $g; $iv[7] ^= $h;
        }

        // 生成最终哈希结果（32位整数转换为 8 位十六进制字符串）
        $result = '';
        foreach ($iv as $v) {
            $result .= sprintf("%08x", $v);
        }
        return $result;
    }
}