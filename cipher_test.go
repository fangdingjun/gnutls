package gnutls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdefg123456789")
	c, err := NewCipher(GNUTLS_CIPHER_AES_128_CBC, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c1, err := NewCipher(GNUTLS_CIPHER_AES_128_CBC, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	data := []byte("1234012121212121")
	if c == nil {
		t.Fatal("new ciphoer failed")
	}
	cdata, err := c.Encrypt(data)
	if err != nil {
		t.Fatal("encrypt failed", err)
	}
	data1, err := c1.Decrypt(cdata)
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
}
