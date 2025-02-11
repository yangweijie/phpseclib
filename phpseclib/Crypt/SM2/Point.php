<?php

namespace phpseclib3\Crypt\SM2;

use Exception;
use phpseclib3\Crypt\SM2\Curves\sm2p256v1;
use phpseclib3\Math\BigInteger;

class Point
{
    protected array $eccParams;
    protected BigInteger $x;
    protected BigInteger $y;
    protected BigInteger $one;
    protected BigInteger $zero;
    protected BigInteger $two;
    protected BigInteger $three;

    public function __construct(BigInteger $x, BigInteger $y)
    {
        $this->x = $x;
        $this->y = $y;
        $this->one = new BigInteger(1);
        $this->two = new BigInteger(2);
        $this->three = new BigInteger(3);
        $this->zero = new BigInteger(0);
        $this->init();
    }

    protected function init()
    {
        static $curve;
        if(!$curve){
            $curve = new sm2p256v1();
        }
        $eccParams = $curve->getParams();
        $this->eccParams = $eccParams;
    }

    public function sign(BigInteger $value): int
    {
        return $value->compare($this->zero) == 0? 0: ($value->compare($this->zero) > 0? 1 : -1);
    }

    public function mod(BigInteger $a, BigInteger $b): BigInteger
    {
        return new BigInteger(intval($a->toString()) % intval($b->toString()));
    }

    public function mul(BigInteger $n, $isBase = true): Point
    {
        $zero = $this->zero;
        $n = $this->mod($n, $this->eccParams['p']);
        if ($this->cmp($n, $zero) === 0) {
            return $this->getInfinity();
        }
        $p = $isBase ? new self($this->eccParams['gx'], $this->eccParams['gy']) : clone $this;
        /** @var Point[] $r */
        $r = [
            $this->getInfinity(), // Q
            $p// P
        ];
        $base = new BigInteger((new BigInteger($n->toString())), 2);
        $n = strrev(str_pad($base, $this->eccParams['size'], '0', STR_PAD_LEFT));
        for ($i = 0; $i < $this->eccParams['size']; $i++) {
            $j = $n[$i];
            if ($j == 1) {
                $r[0] = $r[0]->add($r[1]); // r0 + r1 => p + 0 = p
            }
            $r[1] = $r[1]->getDouble();
        }
        $r[0]->checkOnLine();

        return $r[0];
    }

    public function add(Point $addend): Point
    {
        if ($addend->isInfinity()) {
            return clone $this;
        }

        if ($this->isInfinity()) { // 是否是无穷远点
            return clone $addend;
        }

        // x 相等
        if ($this->cmp($addend->getX(), $this->x) === 0) {
            // y 也相等 = 倍点
            if ($this->cmp($addend->getY(), $this->y) === 0) {
                return $this->getDouble();
            } else { // y 不相等 无穷远点
                return $this->getInfinity();
            }
        }

        $slope = $this->divMod(// λ = (y2 - y1) / (x2 - x1) (mod p)
            $addend->getY()->subtract($this->y),  // y2 - y1
            $addend->getX()->subtract($this->x)  // x2 - x1
        );
        // λ² - x1 - x2
        $xR = $this->subMod($slope->pow($this->two)->subtract($this->x), $addend->getX());
        // (λ(x1 - x3)-y1)
        $yR = $this->subMod($slope->multiply($this->x->subtract($xR)), $this->y);

        return new self($xR, $yR);
    }

    public function getDouble(): Point
    {
        if ($this->isInfinity()) {
            return $this->getInfinity();
        }
        $threeX2 = $this->three->multiply($this->x->pow($this->two)); // 3x²
        $tangent = $this->divMod( // λ = (3x² + a) / 2y (mod p)
            $threeX2->add($this->eccParams['a']),  // 3x² + a
            $this->two->multiply($this->y)  // 2y
        );
        $x3 = $this->subMod(  // λ² - 2x (mod p)
            $tangent->pow($this->two),// λ²
            $this->two->multiply($this->x),// 2x
        );
        $y3 = $this->subMod( // λ(x - x3)-y  (mod p)
            $tangent->multiply($this->x->subtract($x3)), // λ(x - x3)
            $this->y
        );

        return new self($x3, $y3);
    }

    public function getInfinity(): Point
    {
        return new self($this->zero, $this->zero);
    }

    /**
     * @return BigInteger
     */
    public function getX(): BigInteger
    {
        return $this->x;
    }

    /**
     * @return BigInteger
     */
    public function getY()
    {
        return $this->y;
    }

    public function isInfinity(): bool
    {
        return $this->x->compare($this->zero) === 0 && $this->y->compare($this->zero);
    }

    /**
     *  k ≡ (x/y) (mod n) => ky ≡ x (mod n) => k y/x ≡ 1 (mod n)
     * @param BigInteger $x
     * @param BigInteger $y
     * @param BigInteger|null $n
     * @return BigInteger
     */
    protected function divMod(BigInteger $x, BigInteger $y, $n = null): BigInteger
    {
        $n = $n ?: $this->eccParams['p'];
        // y k ≡ 1 (mod n) => k ≡ 1/y (mod n)
        $k = $y->modInverse($n);
        // kx ≡ x/y (mod n)
        $kx = $x->multiply($k);

        return $this->mod($kx, $n);
    }


    protected function subMod(BigInteger $x, BigInteger $y, $n = null): BigInteger
    {
        return $this->mod($x->subtract($y), $n ?: $this->eccParams['p']);
    }

    public function contains(BigInteger $x, BigInteger $y): int
    {
        return $this->cmp(
            $this->subMod(
                $y->pow($this->two),
                ($x->pow($this->three)->add($this->eccParams['a']->multiply($x)))->add($this->eccParams['b']),
            ),
            $this->zero
        );
    }

    public function checkOnLine(): bool
    {
        if ($this->contains($this->x, $this->y) !== 0) {
            throw new Exception('Invalid point');
        }

        return true;
    }

    public function cmp2(BigInteger $a, BigInteger $b): int
    {
        return $a->compare($b);
    }

    /**
     * Compare two GMP objects, without timing leaks.
     *
     * @param BigInteger $first
     * @param BigInteger $other
     * @return int -1 if $first < $other
     *              0 if $first === $other
     *              1 if $first > $other
     */
    public function cmp(
        BigInteger $first,
        BigInteger $other
    ): int {
        /**
         * @var string $left
         * @var string $right
         * @var int $length
         */
        list($left, $right, $length) = $this->normalizeLengths($first, $other);

        $first_sign = $this->sign($first);
        $other_sign = $this->sign($other);
        list($gt, $eq) = $this->compareSigns($first_sign, $other_sign);

        for ($i = 0; $i < $length; ++$i) {
            $gt |= (($this->ord($right[$i]) - $this->ord($left[$i])) >> 8) & $eq;
            $eq &= (($this->ord($right[$i]) ^ $this->ord($left[$i])) - 1) >> 8;
        }
        return ($gt + $gt + $eq) - 1;
    }

    /**
     * Normalize the lengths of two input numbers.
     *
     * @param BigInteger $a
     * @param BigInteger $b
     * @return array<string|int, string|int>
     */
    public function normalizeLengths(
        BigInteger $a,
        BigInteger $b
    ): array {
        $a_hex = $a->abs()->toHex();
        $b_hex = $b->abs()->toHex();
        $length = max(strlen($a_hex), strlen($b_hex));
        $length += $length & 1;

        $left = hex2bin(str_pad($a_hex, $length, '0', STR_PAD_LEFT));
        $right = hex2bin(str_pad($b_hex, $length, '0', STR_PAD_LEFT));
        $length >>= 1;
        return [$left, $right, $length];
    }

    /**
     * Compare signs. Returns [$gt, $eq].
     *
     * Sets $gt to 1 if $first > $other.
     * Sets $eq to1 if $first === $other.
     *
     * See {@link cmp()} for usage.
     *
     * | first | other | gt | eq |
     * |-------|-------|----|----|
     * |    -1 |    -1 |  0 |  1 |
     * |    -1 |     0 |  0 |  0 |
     * |    -1 |     1 |  0 |  0 |
     * |     0 |    -1 |  1 |  0 |
     * |     0 |     0 |  0 |  1 |
     * |     0 |     1 |  1 |  0 |
     * |     1 |    -1 |  1 |  0 |
     * |     1 |     0 |  1 |  0 |
     * |     1 |     1 |  0 |  1 |
     *
     * @param int $first_sign
     * @param int $other_sign
     * @return int[]
     */
    public function compareSigns(
        int $first_sign,
        int $other_sign
    ): array {
        // Coerce to positive (-1, 0, 1) -> (0, 1, 2)
        ++$first_sign;
        ++$other_sign;
        $gt = (($other_sign - $first_sign) >> 2) & 1;
        $eq = ((($first_sign ^ $other_sign) - 1) >> 2) & 1;
        return [$gt, $eq];
    }

    /**
     * Get an unsigned integer for the character in the provided string at index 0.
     *
     * @param string $chr
     * @return int
     */
    public function ord(
        string $chr
    ): int {
        // return (int) unpack('C', $chr)[1];
        $packArr = unpack('C', $chr);
        return (int) $packArr[1];
    }
}