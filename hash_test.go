package gnutls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"runtime"
	"testing"
	"time"
)

func TestHashSHA(t *testing.T) {
	h := NewHash(GNUTLS_HASH_SHA512)
	//defer h.Close()

	data := []byte("1234")

	h1 := h.Sum(data)

	h3 := sha512.New()
	h3.Write(data)
	h4 := h3.Sum(nil)
	if !bytes.Equal(h4[:], h1) {
		log.Printf("\n%s\n%s", hex.EncodeToString(h4[:]), hex.EncodeToString(h1))
		t.Fatal("hash not equal")
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func BenchmarkHashSHA512(b *testing.B) {
	buf := make([]byte, 1000*1024)
	rand.Reader.Read(buf)
	for i := 0; i < b.N; i++ {
		h := NewHash(GNUTLS_HASH_SHA512)
		h.Write(buf)
		h.Sum(nil)
		h.Close()
	}
}

func BenchmarkHashSHA512s(b *testing.B) {
	buf := make([]byte, 1000*1024)
	rand.Reader.Read(buf)
	for i := 0; i < b.N; i++ {
		h := sha512.New()
		h.Write(buf)
		h.Sum(nil)
		//h.Close()
	}
}
