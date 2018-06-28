package gnutls

/*
#include "_gnutls.h"
#cgo pkg-config: gnutls
*/
import "C"
import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unsafe"
)

const (
	GNUTLS_NAME_DNS     = 1
	GNUTLS_X509_FMT_PEM = 1
)

// Conn tls connection for client
type Conn struct {
	c         net.Conn
	sess      *C.struct_session
	handshake bool
	cservname *C.char
}

// Config tls configure
type Config struct {
	ServerName         string
	CrtFile            string
	KeyFile            string
	InsecureSkipVerify bool
}
type listener struct {
	l net.Listener
	c *Config
}

// Accept
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return NewServerConn(c, l.c)
}

// Close
func (l *listener) Close() error {
	return l.l.Close()
}

// Addr
func (l *listener) Addr() net.Addr {
	return l.l.Addr()
}

// Dial create a new connection
func Dial(network, addr string, cfg *Config) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewClientConn(c, cfg)
}

// Listen create a listener
func Listen(network, addr string, cfg *Config) (net.Listener, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is need")
	}
	if cfg.CrtFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("keyfile is needed")
	}
	if _, err := os.Stat(cfg.CrtFile); err != nil {
		return nil, err
	}
	if _, err := os.Stat(cfg.KeyFile); err != nil {
		return nil, err
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &listener{l, cfg}, nil
}

// NewServerConn create a server Conn
func NewServerConn(c net.Conn, cfg *Config) (*Conn, error) {
	var sess = C.init_server_session()
	conn := &Conn{c: c, sess: sess}
	n := C.size_t(uintptr(unsafe.Pointer(conn)))
	//log.Println("conn addr ", int(n))
	C.set_data(sess, n)
	C.set_callback(sess)
	crtfile := C.CString(cfg.CrtFile)
	keyfile := C.CString(cfg.KeyFile)
	defer C.free(unsafe.Pointer(crtfile))
	defer C.free(unsafe.Pointer(keyfile))
	ret := C.gnutls_certificate_set_x509_key_file(
		sess.xcred, crtfile, keyfile, GNUTLS_X509_FMT_PEM)
	if int(ret) < 0 {
		cerrstr := C.gnutls_strerror(ret)
		return nil, fmt.Errorf("set keyfile failed: %s", C.GoString(cerrstr))
	}
	return conn, nil
}

// NewClientConn create a new gnutls connection
func NewClientConn(c net.Conn, cfg *Config) (*Conn, error) {
	var sess = C.init_client_session()
	conn := &Conn{c: c, sess: sess}
	n := C.size_t(uintptr(unsafe.Pointer(conn)))
	//log.Println("conn addr ", int(n))
	C.set_data(sess, n)
	C.set_callback(sess)
	if cfg != nil {
		if cfg.ServerName != "" {
			srvname := C.CString(cfg.ServerName)
			//defer C.free(unsafe.Pointer(srvname))
			conn.cservname = srvname
			C.gnutls_server_name_set(sess.session, GNUTLS_NAME_DNS,
				unsafe.Pointer(srvname), C.size_t(len(cfg.ServerName)))
		}

		if cfg.CrtFile != "" && cfg.KeyFile != "" {
			crtfile := C.CString(cfg.CrtFile)
			keyfile := C.CString(cfg.KeyFile)
			defer C.free(unsafe.Pointer(crtfile))
			defer C.free(unsafe.Pointer(keyfile))
			ret := C.gnutls_certificate_set_x509_key_file(
				sess.xcred, crtfile, keyfile, GNUTLS_X509_FMT_PEM)
			if int(ret) < 0 {
				return nil, fmt.Errorf("set keyfile failed: %s",
					C.GoString(C.gnutls_strerror(ret)))
			}
		}
		if !cfg.InsecureSkipVerify {
			if conn.cservname != nil {
				C.gnutls_session_set_verify_cert(sess.session, conn.cservname, 0)
			} else {
				C.gnutls_session_set_verify_cert(sess.session, nil, 0)
			}
		}
	} else {
		C.gnutls_session_set_verify_cert(sess.session, nil, 0)
	}
	return conn, nil
}

// Handshake handshake tls
func (c *Conn) Handshake() error {
	if c.handshake {
		return nil
	}
	ret := C.handshake(c.sess)
	if int(ret) < 0 {
		return fmt.Errorf("handshake error")
	}
	c.handshake = true
	//log.Println("handshake done")
	return nil
}

// Read read data from tls connection
func (c *Conn) Read(buf []byte) (n int, err error) {
	if !c.handshake {
		err = c.Handshake()
		if err != nil {
			return
		}
		c.handshake = true
	}

	bufLen := len(buf)
	cbuf := C.malloc(C.size_t(bufLen))
	defer C.free(cbuf)

	ret := C.gnutls_record_recv(c.sess.session, cbuf, C.size_t(bufLen))
	if int(ret) < 0 {
		return 0, fmt.Errorf("read error: %s",
			C.GoString(C.gnutls_strerror(C.int(ret))))
	}

	if int(ret) == 0 {
		return 0, fmt.Errorf("connection closed")
	}

	n = int(ret)
	gobuf2 := C.GoBytes(cbuf, C.int(ret))
	copy(buf, gobuf2)
	return n, nil
}

// Write write data to tls connection
func (c *Conn) Write(buf []byte) (n int, err error) {
	if !c.handshake {
		err = c.Handshake()
		if err != nil {
			return
		}
		c.handshake = true
	}
	cbuf := C.CBytes(buf)
	defer C.free(cbuf)

	ret := C.gnutls_record_send(c.sess.session, cbuf, C.size_t(len(buf)))
	n = int(ret)

	if n < 0 {
		return 0, fmt.Errorf("write error: %s",
			C.GoString(C.gnutls_strerror(C.int(ret))))
	}

	if int(ret) == 0 {
		return 0, fmt.Errorf("connection closed")
	}

	return n, nil
}

// Close close the conn and destroy the tls context
func (c *Conn) Close() error {
	C.session_destroy(c.sess)
	c.c.Close()
	if c.cservname != nil {
		C.free(unsafe.Pointer(c.cservname))
	}
	return nil
}

// SetWriteDeadline implements net.Conn
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// RemoteAddr implements net.Conn
func (c *Conn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

// LocalAddr implements net.Conn
func (c *Conn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

// SetDeadline implements net.Conn
func (c *Conn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// DataRead c callback function for data read
//export DataRead
func DataRead(d unsafe.Pointer, cbuf *C.char, bufLen C.int) C.int {
	//log.Println("read addr ", uintptr(d))
	conn := (*Conn)(unsafe.Pointer((uintptr(d))))
	buf := make([]byte, int(bufLen))
	n, err := conn.c.Read(buf)
	if err != nil {
		log.Println(err)
		return -1
	}
	cbuf2 := C.CBytes(buf[:n])
	// d := C.CString(string(buf[:n]))
	defer C.free(cbuf2)
	C.memcpy(unsafe.Pointer(cbuf), unsafe.Pointer(cbuf2), C.size_t(n))
	return C.int(n)
}

// DataWrite c callback function for data write
//export DataWrite
func DataWrite(d unsafe.Pointer, cbuf *C.char, bufLen C.int) C.int {
	//log.Println("write addr ", uintptr(d), int(_l))
	conn := (*Conn)(unsafe.Pointer((uintptr(d))))
	gobuf := C.GoBytes(unsafe.Pointer(cbuf), bufLen)
	n, err := conn.c.Write(gobuf)
	if err != nil {
		log.Println(err)
		return -1
	}
	return C.int(n)
}

// DataTimeoutPull c callback function for timeout read
//export DataTimeoutPull
func DataTimeoutPull(d unsafe.Pointer, delay C.int) C.int {
	log.Println("timeout pull function")
	return 0
}
