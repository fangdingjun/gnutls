package gnutls

/*
#include <stdlib.h>
#include "_gnutls.h"
*/
import "C"
import (
	"fmt"
)

const (
	GNUTLS_HASH_MD5    = 2
	GNUTLS_HASH_SHA1   = 3
	GNUTLS_HASH_MD2    = 5
	GNUTLS_HASH_SHA256 = 6
	GNUTLS_HASH_SHA384 = 7
	GNUTLS_HASH_SHA512 = 8
	GNUTLS_HASH_SHA224 = 9
)

// Hash hash struct
type Hash struct {
	hash    C.gnutls_hash_hd_t
	t       int
	hashLen C.int
}

// NewHash new hash struct
func NewHash(t int) *Hash {
	h := C.new_hash(C.int(t))
	hashOutLen := GetHashOutputLen(t)
	return &Hash{h, t, C.int(hashOutLen)}
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
	C.gnutls_hash_deinit(h.hash, nil)
	return nil
}

// GetHashOutputLen get the hash algorithm output length
// example GNUTLS_MD5 is 16
func GetHashOutputLen(t int) int {
	return int(C.gnutls_hash_get_len(C.gnutls_digest_algorithm_t(t)))
}
