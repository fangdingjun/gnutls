package gnutls

/*
#include <stdlib.h>
#include "_gnutls.h"
*/
import "C"
import (
	"fmt"
	"runtime"
)

// HashType hash type
type HashType int

const (
	GNUTLS_HASH_MD5    HashType = 2
	GNUTLS_HASH_SHA1   HashType = 3
	GNUTLS_HASH_MD2    HashType = 5
	GNUTLS_HASH_SHA256 HashType = 6
	GNUTLS_HASH_SHA384 HashType = 7
	GNUTLS_HASH_SHA512 HashType = 8
	GNUTLS_HASH_SHA224 HashType = 9
)

// Hash hash struct
type Hash struct {
	hash    C.gnutls_hash_hd_t
	t       HashType
	hashLen C.int
}

// NewHash new hash struct
func NewHash(t HashType) *Hash {
	h := C.new_hash(C.int(t))
	hashOutLen := GetHashOutputLen(t)
	hash := &Hash{h, t, C.int(hashOutLen)}
	runtime.SetFinalizer(hash, (*Hash).free)
	return hash
}

// Write write data to hash context
func (h *Hash) Write(buf []byte) error {
	dataLen := len(buf)

	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	ret := C.gnutls_hash(h.hash, cbuf, C.size_t(dataLen))
	if int(ret) < 0 {
		return fmt.Errorf("hash failed: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	return nil
}

// Sum get hash result
func (h *Hash) Sum(buf []byte) []byte {
	if buf != nil {
		h.Write(buf)
	}

	dstBuf := C.malloc(C.size_t(h.hashLen))
	defer C.free(dstBuf)

	C.gnutls_hash_output(h.hash, dstBuf)

	gobuf := C.GoBytes(dstBuf, h.hashLen)

	return gobuf
}

// Close destroy hash context
func (h *Hash) Close() error {
	if h.hash != nil {
		C.gnutls_hash_deinit(h.hash, nil)
		h.hash = nil
	}
	return nil
}
func (h *Hash) free() {
	//log.Println("free hash")
	h.Close()
}

// GetHashOutputLen get the hash algorithm output length
//
// example GNUTLS_MD5 is 16
func GetHashOutputLen(t HashType) int {
	return int(C.gnutls_hash_get_len(C.gnutls_digest_algorithm_t(t)))
}
