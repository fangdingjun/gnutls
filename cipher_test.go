package gnutls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"runtime"
	"testing"
	"time"
)

func TestCipherSize(t *testing.T) {
	data := []struct {
		t     CipherType
		bsize int
		isize int
	}{
		{GNUTLS_CIPHER_AES_128_CBC, 16, 16},
		{GNUTLS_CIPHER_AES_192_CBC, 24, 16},
		{GNUTLS_CIPHER_AES_256_CBC, 32, 16},
	}
	for _, d := range data {
		blocksize := GetCipherKeySize(d.t)
		if blocksize != d.bsize {
			t.Errorf("%d block size expect: %d, got: %d", d.t, d.bsize, blocksize)
		}
		ivsize := GetCipherIVSize(d.t)
		if ivsize != d.isize {
			t.Errorf("%d iv size expect: %d, got: %d", d.t, d.bsize, ivsize)
		}
	}
}
func TestEncryptDecrypt(t *testing.T) {
	cipherName := GNUTLS_CIPHER_AES_256_CBC
	keysize := GetCipherKeySize(cipherName)
	ivsize := GetCipherIVSize(cipherName)
	blocksize := GetCipherBlockSize(cipherName)

	key := make([]byte, keysize)
	iv := make([]byte, ivsize)
	rand.Reader.Read(key)
	rand.Reader.Read(iv)

	c, err := NewCipher(cipherName, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	//defer c.Close()

	c1, err := NewCipher(cipherName, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	//defer c1.Close()

	data := make([]byte, blocksize*10)
	if c == nil {
		t.Fatal("new ciphoer failed")
	}
	cdata := make([]byte, len(data))
	err = c.Encrypt(cdata, data)
	if err != nil {
		t.Fatal("encrypt failed", err)
	}
	data1 := make([]byte, len(data))
	err = c1.Decrypt(data1, cdata)
	if err != nil {
		t.Fatal("decrypt failed", err)
	}
	if !bytes.Equal(data, data1) {
		t.Fatal("encrypt/decrypt failed", string(data), string(data1))
	}
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, len(data))
	mode.CryptBlocks(dst, data)
	if !bytes.Equal(dst, cdata) {
		t.Fatal("cipher text not equal to cypto/aes")
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func BenchmarkAESEncrypt(b *testing.B) {
	cipherName := GNUTLS_CIPHER_AES_256_CBC
	keysize := GetCipherKeySize(cipherName)
	ivsize := GetCipherIVSize(cipherName)
	blocksize := GetCipherBlockSize(cipherName)
	datalen := blocksize * 500

	key := make([]byte, keysize)
	iv := make([]byte, ivsize)
	rand.Reader.Read(key)
	rand.Reader.Read(iv)
	buf := make([]byte, datalen)
	dst := make([]byte, datalen)
	for i := 0; i < b.N; i++ {
		c, err := NewCipher(cipherName, key, iv)
		if err != nil {
			b.Fatal(err)
		}
		c.Encrypt(dst, buf)
		c.Close()
	}
}

func BenchmarkAESEncrypt2(b *testing.B) {
	cipherName := GNUTLS_CIPHER_AES_256_CBC
	keysize := GetCipherKeySize(cipherName)
	ivsize := GetCipherIVSize(cipherName)
	blocksize := GetCipherBlockSize(cipherName)
	datalen := blocksize * 500

	key := make([]byte, keysize)
	iv := make([]byte, ivsize)
	buf := make([]byte, datalen)

	rand.Reader.Read(buf)
	rand.Reader.Read(key)
	rand.Reader.Read(iv)

	dst := make([]byte, datalen)

	for i := 0; i < b.N; i++ {
		block, _ := aes.NewCipher(key)
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(dst, buf)
	}
}
