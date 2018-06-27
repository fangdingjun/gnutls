package gnutls

/*
#include "_gnutls.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"log"
)

const (
	GNUTLS_CIPHER_AES_128_CBC         = 4
	GNUTLS_CIPHER_AES_256_CBC         = 5
	GNUTLS_CIPHER_ARCFOUR_40          = 6
	GNUTLS_CIPHER_CAMELLIA_128_CBC    = 7
	GNUTLS_CIPHER_CAMELLIA_256_CBC    = 8
	GNUTLS_CIPHER_AES_192_CBC         = 9
	GNUTLS_CIPHER_AES_128_GCM         = 10
	GNUTLS_CIPHER_AES_256_GCM         = 11
	GNUTLS_CIPHER_CAMELLIA_192_CBC    = 12
	GNUTLS_CIPHER_SALSA20_256         = 13
	GNUTLS_CIPHER_ESTREAM_SALSA20_256 = 14
	GNUTLS_CIPHER_CAMELLIA_128_GCM    = 15
	GNUTLS_CIPHER_CAMELLIA_256_GCM    = 16
	GNUTLS_CIPHER_RC2_40_CBC          = 17
	GNUTLS_CIPHER_DES_CBC             = 18
	GNUTLS_CIPHER_AES_128_CCM         = 19
	GNUTLS_CIPHER_AES_256_CCM         = 20
	GNUTLS_CIPHER_AES_128_CCM_8       = 21
	GNUTLS_CIPHER_AES_256_CCM_8       = 22
	GNUTLS_CIPHER_CHACHA20_POLY1305   = 23
)

// Cipher cipher
type Cipher struct {
	cipher C.gnutls_cipher_hd_t
	t      int
}

// NewCipher create cipher
func NewCipher(t int, key []byte, iv []byte) (*Cipher, error) {
	ivSize := C.cipher_get_block_size(C.int(t))
	blockSize := C.cipher_get_iv_size(C.int(t))
	if len(key) != int(blockSize) || len(iv) != int(ivSize) {

		return nil, fmt.Errorf("wrong block/iv size")
	}

	ckey := C.CBytes(key)
	civ := C.CBytes(iv)

	defer C.free(ckey)
	defer C.free(civ)

	c := C.new_cipher(C.int(t), (*C.char)(ckey), C.int(len(key)), (*C.char)(civ), C.int(len(iv)))
	if c == nil {
		log.Println("new cipher return nil")
		return nil, nil
	}
	return &Cipher{c, t}, nil
}

// Encrypt encrypt
func (c *Cipher) Encrypt(buf []byte) ([]byte, error) {
	blockSize := C.cipher_get_iv_size(C.int(c.t))
	if len(buf)%int(blockSize) != 0 {
		return nil, fmt.Errorf("wrong block size")
	}

	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	bufLen := C.size_t(len(buf))
	dstBuf := C.malloc(bufLen)

	defer C.free(dstBuf)

	ret := C.gnutls_cipher_encrypt2(c.cipher, cbuf, bufLen, dstBuf, bufLen)
	if int(ret) < 0 {
		return nil, fmt.Errorf("encrypt error: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	return C.GoBytes(dstBuf, C.int(bufLen)), nil
}

// Decrypt decrypt
func (c *Cipher) Decrypt(buf []byte) ([]byte, error) {
	blockSize := C.cipher_get_iv_size(C.int(c.t))
	if len(buf)%int(blockSize) != 0 {
		return nil, fmt.Errorf("wrong block size")
	}

	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	bufLen := C.size_t(len(buf))
	dstBuf := C.malloc(C.size_t(len(buf)))

	defer C.free(dstBuf)

	ret := C.gnutls_cipher_decrypt2(c.cipher, cbuf, bufLen, dstBuf, bufLen)
	if int(ret) < 0 {
		return nil, fmt.Errorf("decrypt error: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	return C.GoBytes(dstBuf, C.int(bufLen)), nil
}

// Close destroy the cipher
func (c *Cipher) Close() error {
	C.gnutls_cipher_deinit(c.cipher)
	return nil
}
