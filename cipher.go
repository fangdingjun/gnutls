package gnutls

/*
#include "_gnutls.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	"runtime"
)

// CipherType cipher type
type CipherType int

const (
	GNUTLS_CIPHER_AES_128_CBC         CipherType = 4
	GNUTLS_CIPHER_AES_256_CBC         CipherType = 5
	GNUTLS_CIPHER_ARCFOUR_40          CipherType = 6
	GNUTLS_CIPHER_CAMELLIA_128_CBC    CipherType = 7
	GNUTLS_CIPHER_CAMELLIA_256_CBC    CipherType = 8
	GNUTLS_CIPHER_AES_192_CBC         CipherType = 9
	GNUTLS_CIPHER_AES_128_GCM         CipherType = 10
	GNUTLS_CIPHER_AES_256_GCM         CipherType = 11
	GNUTLS_CIPHER_CAMELLIA_192_CBC    CipherType = 12
	GNUTLS_CIPHER_SALSA20_256         CipherType = 13
	GNUTLS_CIPHER_ESTREAM_SALSA20_256 CipherType = 14
	GNUTLS_CIPHER_CAMELLIA_128_GCM    CipherType = 15
	GNUTLS_CIPHER_CAMELLIA_256_GCM    CipherType = 16
	GNUTLS_CIPHER_RC2_40_CBC          CipherType = 17
	GNUTLS_CIPHER_DES_CBC             CipherType = 18
	GNUTLS_CIPHER_AES_128_CCM         CipherType = 19
	GNUTLS_CIPHER_AES_256_CCM         CipherType = 20
	GNUTLS_CIPHER_AES_128_CCM_8       CipherType = 21
	GNUTLS_CIPHER_AES_256_CCM_8       CipherType = 22
	GNUTLS_CIPHER_CHACHA20_POLY1305   CipherType = 23
)

var (
	// ErrBlockSize wrong block size
	ErrBlockSize = errors.New("wrong block size")
	// ErrKeyLength wrong key length
	ErrKeyLength = errors.New("wrong key length")
	// ErrIVLength wrong iv length
	ErrIVLength = errors.New("wrong iv length")
)

// Cipher gnutls cipher struct
type Cipher struct {
	cipher    C.gnutls_cipher_hd_t
	t         CipherType
	blockSize int
}

// NewCipher create a new cipher by give type, key, iv
//
// example:
// 	   NewCipher(GNUTLS_CIPHER_AES_128_CBC, []byte("1234567890abcdef"), []byte("abcdef0123456789"))
//
// you can use GetCipherKeySize, GetCipherBlockSize, GetCipherIVSize to determine the given cipher 's key, block, iv size
func NewCipher(t CipherType, key []byte, iv []byte) (*Cipher, error) {
	keysize := GetCipherKeySize(t)
	ivSize := GetCipherIVSize(t)
	blocksize := GetCipherBlockSize(t)
	//log.Printf("block size: %d, iv size: %d", int(ivSize), int(blockSize))
	if len(key) != int(keysize) {
		return nil, ErrKeyLength
	}

	if len(iv) != int(ivSize) {
		return nil, ErrIVLength
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
	cipher := &Cipher{c, t, blocksize}
	runtime.SetFinalizer(cipher, (*Cipher).free)
	return cipher, nil
}

// Encrypt encrypt the buf and place the encrypted data in dst,
// the buf size must multiple of cipher's block size
func (c *Cipher) Encrypt(dst, buf []byte) error {
	if len(buf)%c.blockSize != 0 {
		return ErrBlockSize
	}

	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	bufLen := C.size_t(len(buf))
	dstBuf := C.malloc(bufLen)

	defer C.free(dstBuf)

	ret := C.gnutls_cipher_encrypt2(c.cipher, cbuf, bufLen, dstBuf, bufLen)
	if int(ret) < 0 {
		return fmt.Errorf("encrypt error: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	_buf := C.GoBytes(dstBuf, C.int(bufLen))
	copy(dst, _buf)
	return nil
}

// Decrypt decrypt the buf and place the decrypted data in dst,
// the buf size must multiple of cipher's block size
func (c *Cipher) Decrypt(dst, buf []byte) error {
	if len(buf)%c.blockSize != 0 {
		return ErrBlockSize
	}

	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	bufLen := C.size_t(len(buf))
	dstBuf := C.malloc(C.size_t(len(buf)))

	defer C.free(dstBuf)

	ret := C.gnutls_cipher_decrypt2(c.cipher, cbuf, bufLen, dstBuf, bufLen)
	if int(ret) < 0 {
		return fmt.Errorf("decrypt error: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	_buf := C.GoBytes(dstBuf, C.int(bufLen))
	copy(dst, _buf)
	return nil
}

// Close destroy the cipher context
func (c *Cipher) Close() error {
	if c.cipher != nil {
		C.gnutls_cipher_deinit(c.cipher)
		c.cipher = nil
	}
	return nil
}

func (c *Cipher) free() {
	log.Println("free cipher")
	c.Close()
}

// GetCipherKeySize get the cipher algorithm key length
func GetCipherKeySize(t CipherType) int {
	return int(C.gnutls_cipher_get_key_size(C.gnutls_cipher_algorithm_t(t)))
}

// GetCipherIVSize get the cipher algorithm iv length
func GetCipherIVSize(t CipherType) int {
	return int(C.gnutls_cipher_get_iv_size(C.gnutls_cipher_algorithm_t(t)))
}

// GetCipherBlockSize get the cipher algorithm block size
func GetCipherBlockSize(t CipherType) int {
	return int(C.gnutls_cipher_get_block_size(C.gnutls_cipher_algorithm_t(t)))
}
