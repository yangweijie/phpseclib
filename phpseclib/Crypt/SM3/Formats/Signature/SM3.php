<?php
declare(strict_types=1);

namespace phpseclib3\Crypt\SM3\Formats\Signature;

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Crypt\SM3\SM3Digest;

class SM3 extends BlockCipher
{

    protected $key_length = 0;

    public function __construct(string $mode)
    {
        parent::__construct('stream');
        $this->setKey('');
    }

    /**
     * Sets the engine as appropriate
     *
     * @see self::__construct()
     */
    protected function setEngine(): void
    {
        $this->engine = null;

        $candidateEngines = [
            self::ENGINE_OPENSSL,
            self::ENGINE_EVAL,
        ];
        foreach ($candidateEngines as $engine) {
            if ($this->isValidEngineHelper($engine)) {
                $this->engine = $engine;
                break;
            }
        }
        if (!$this->engine) {
            $this->engine = self::ENGINE_INTERNAL;
        }
        $this->changed = $this->nonIVChanged = true;
    }

    protected function isValidEngineHelper(int $engine): bool
    {
        if ($engine == self::ENGINE_OPENSSL) {
            $this->cipher_name_openssl = 'sm3';
            if(in_array($this->cipher_name_openssl, openssl_get_md_methods())) {
                return true;
            }else{
                return false;
            }
        }else{
            return true;
        }
    }

    public function sign(string $plaintext): string
    {
        $this->setup();
        if($this->engine == self::ENGINE_OPENSSL) {
            return openssl_digest($plaintext, $this->cipher_name_openssl);
        }else{
            return SM3Digest::hash($plaintext);
        }
    }

    protected function encryptBlock(string $in): string
    {
        return '';
    }

    protected function decryptBlock(string $in): string
    {
        throw new \RuntimeException('Not support');
    }

    protected function setupKey()
    {

    }
}