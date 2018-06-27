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
	GNUTLS_MD5    = 2
	GNUTLS_SHA1   = 3
	GNUTLS_MD2    = 5
	GNUTLS_SHA256 = 6
	GNUTLS_SHA384 = 7
	GNUTLS_SHA512 = 8
	GNUTLS_SHA224 = 9
)

// Hash hash struct
type Hash struct {
	hash C.gnutls_hash_hd_t
	t    int
}

// NewHash new hash struct
func NewHash(t int) *Hash {
	h := C.new_hash(C.int(t))
	return &Hash{h, t}
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

	hashOutLen := C.get_hash_len(C.int(h.t))

	dstBuf := C.malloc(C.size_t(hashOutLen))
	defer C.free(dstBuf)

	C.gnutls_hash_output(h.hash, dstBuf)

	gobuf := C.GoBytes(dstBuf, hashOutLen)

	return gobuf
}

// Close destroy hash context
func (h *Hash) Close() error {
	C.gnutls_hash_deinit(h.hash, nil)
	return nil
}
