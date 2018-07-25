package gnutls

/*
#include "_gnutls.h"
*/
import "C"
import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"unsafe"
)

// Certificate x509 certificate
type Certificate struct {
	cert     *C.gnutls_pcert_st
	privkey  C.gnutls_privkey_t
	certSize C.int
}

// Free free the certificate context
func (c *Certificate) Free() {
	if c.cert != nil {
		C.free_cert_list(c.cert, c.certSize)
	}
	if c.privkey != nil {
		C.gnutls_privkey_deinit(c.privkey)
	}
	c.cert = nil
	c.privkey = nil
	c.certSize = 0
}

func (c *Certificate) free() {
	//log.Println("free certificate")
	c.Free()
}

func (c *Certificate) matchName(name string) bool {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	ret := C.cert_check_hostname(c.cert, c.certSize, cname)
	if int(ret) < 0 {
		log.Println(C.GoString(C.gnutls_strerror(ret)))
		return false
	}
	if int(ret) > 0 {
		return true
	}
	return false
}

// CommonName get CN field in subject,
//
// example: subject C=xx,ST=bbb,CN=abc will return abc
func (c *Certificate) CommonName() string {
	return c.commonName(0)
}
func (c *Certificate) commonName(index int) string {
	dnMap := make(map[string]string)
	dn := c.getDN(0)
	if dn != "" {
		dnFields := strings.Split(dn, ",")
		for _, d := range dnFields {
			dd := strings.Split(d, "=")
			k := dd[0]
			v := dd[1]
			dnMap[k] = v
		}
	}

	if cn, ok := dnMap["CN"]; ok {
		return cn
	}
	return ""
}

// GetAltName get altname in certificate
func (c *Certificate) GetAltName() string {
	return c.getAltName(0, 0)
}
func (c *Certificate) getAltName(index int, nameindex int) string {
	out := C.malloc(1024)
	defer C.free(out)
	size := C.get_pcert_alt_name(
		c.cert, C.int(index), C.int(nameindex), (*C.char)(out))
	if int(size) < 0 {
		log.Println(C.GoString(C.gnutls_strerror(size)))
		return ""
	}

	name := C.GoBytes(out, size)
	return string(name)
}

//GetCertString return certificate info string in one line
func (c *Certificate) GetCertString() string {
	return c.getCertString(0, 1)
}

func (c *Certificate) getCertString(index int, flag int) string {
	out := C.malloc(4096)
	defer C.free(out)
	size := C.get_cert_str(c.cert, C.int(index), C.int(flag), (*C.char)(out))
	if int(size) < 0 {
		log.Println(C.GoString(C.gnutls_strerror(size)))
		return ""
	}
	s := C.GoBytes(out, size)
	return string(s)
}

// GetDN get the certificate subject, like O=st,C=aa,CN=localhost
func (c *Certificate) GetDN() string {
	return c.getDN(0)
}

func (c *Certificate) getDN(index int) string {
	cbuf := C.malloc(200)
	defer C.free(cbuf)
	size := C.get_cert_dn(c.cert, C.int(index), (*C.char)(cbuf))
	if int(size) < 0 {
		log.Println(C.GoString(C.gnutls_strerror(size)))
		return ""
	}
	s := C.GoBytes(cbuf, size)
	return string(s)
}

// GetIssuerDN get the certificate issuer's subject, like O=st,C=ac,CN=localhost
func (c *Certificate) GetIssuerDN() string {
	return c.getIssuerDN(0)
}

func (c *Certificate) getIssuerDN(index int) string {
	cbuf := C.malloc(200)
	defer C.free(cbuf)
	size := C.get_cert_issuer_dn(c.cert, C.int(index), (*C.char)(cbuf))
	if int(size) < 0 {
		log.Println(C.GoString(C.gnutls_strerror(size)))
		return ""
	}
	s := C.GoBytes(cbuf, size)
	return string(s)
}

// LoadX509KeyPair load certificate pair,
// the return Certifciate must be freed by call Free(),
func LoadX509KeyPair(certfile, keyfile string) (*Certificate, error) {
	_certfile := C.CString(certfile)
	_keyfile := C.CString(keyfile)

	defer C.free(unsafe.Pointer(_certfile))
	defer C.free(unsafe.Pointer(_keyfile))

	certificate := &Certificate{}
	var ret C.int
	var certSize C.int
	cert := C.load_cert_list(_certfile, (*C.int)(unsafe.Pointer(&certSize)),
		(*C.int)(unsafe.Pointer(&ret)))
	if int(ret) < 0 {
		return nil, fmt.Errorf("load cert failed: %s",
			C.GoString(C.gnutls_strerror(ret)))
	}
	privkey := C.load_privkey(_keyfile, (*C.int)(unsafe.Pointer(&ret)))
	if int(ret) < 0 {
		return nil, fmt.Errorf("load privkey: %s",
			C.GoString(C.gnutls_strerror(ret)))
	}
	certificate.cert = cert
	certificate.privkey = privkey
	certificate.certSize = certSize
	runtime.SetFinalizer(certificate, (*Certificate).free)
	return certificate, nil
}
