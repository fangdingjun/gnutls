package gnutls

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"testing"
)

func TestHashSHA(t *testing.T) {
	h := NewHash(GNUTLS_SHA512)
	defer h.Close()

	data := []byte("1234")

	h1 := h.Sum(data)

	h3 := sha512.Sum512(data)
	if !bytes.Equal(h3[:], h1) {
		log.Printf("\n%s\n%s", hex.EncodeToString(h3[:]), hex.EncodeToString(h1))
		t.Fatal("hash not equal")
	}
}
