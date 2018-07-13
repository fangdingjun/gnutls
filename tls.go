package gnutls

/*
#include "_gnutls.h"
#cgo pkg-config: gnutls
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const (
	GNUTLS_NAME_DNS               = 1
	GNUTLS_X509_FMT_PEM           = 1
	GNUTLS_ALPN_MANDATORY         = 1
	GNUTLS_ALPN_SERVER_PRECEDENCE = 1 << 1
)

// Conn gnutls TLS connection,
// use Listen, Dial, Server or Client create this object
type Conn struct {
	c         net.Conn
	handshake bool
	sess      *C.struct_session
	cservname *C.char
	state     *ConnectionState
	cfg       *Config
	closed    bool
	lock      *sync.Mutex
}

// Config gnutls TLS configure,
type Config struct {
	ServerName         string
	Certificates       []*Certificate
	InsecureSkipVerify bool
	NextProtos         []string
}

// ConnectionState gnutls TLS connection state
type ConnectionState struct {
	// SNI name client send
	ServerName string
	// selected ALPN protocl
	NegotiatedProtocol string
	HandshakeComplete  bool
	// TLS version number, ex: 0x303
	Version uint16
	// TLS version number, ex: TLS1.0
	VersionName string
	// peer's certificate
	PeerCertificate *Certificate
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
	return Server(c, l.c)
}

// Close
func (l *listener) Close() error {
	return l.l.Close()
}

// Addr
func (l *listener) Addr() net.Addr {
	return l.l.Addr()
}

// Dial dial to (network, addr) and create a gnutls Conn
func Dial(network, addr string, cfg *Config) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return Client(c, cfg)
}

// Listen create a gnutls listener on (network, addr),
func Listen(network, addr string, cfg *Config) (net.Listener, error) {
	if cfg == nil {
		return nil, errors.New("config is needed")
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &listener{l, cfg}, nil
}

// Server create a server TLS Conn on c
func Server(c net.Conn, cfg *Config) (*Conn, error) {
	var sess = C.init_gnutls_server_session()
	conn := &Conn{c: c, sess: sess, cfg: cfg, lock: new(sync.Mutex)}
	n := C.size_t(uintptr(unsafe.Pointer(conn)))
	//log.Println("conn addr ", int(n))
	C.set_data(sess, n)
	C.set_callback(sess)

	if cfg.NextProtos != nil {
		if err := setAlpnProtocols(sess, cfg); err != nil {
			log.Println(err)
		}
	}
	runtime.SetFinalizer(conn, (*Conn).free)
	return conn, nil
}

// Client create a client TLS Conn on c
func Client(c net.Conn, cfg *Config) (*Conn, error) {
	var sess = C.init_gnutls_client_session()
	conn := &Conn{c: c, sess: sess, cfg: cfg, lock: new(sync.Mutex)}
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

		if !cfg.InsecureSkipVerify {
			if conn.cservname != nil {
				C.gnutls_session_set_verify_cert(sess.session, conn.cservname, 0)
			} else {
				C.gnutls_session_set_verify_cert(sess.session, nil, 0)
			}
		}

		if cfg.NextProtos != nil {
			if err := setAlpnProtocols(sess, cfg); err != nil {
				log.Println(err)
			}
		}

	} else {
		C.gnutls_session_set_verify_cert(sess.session, nil, 0)
	}
	runtime.SetFinalizer(conn, (*Conn).free)
	return conn, nil
}

func setAlpnProtocols(sess *C.struct_session, cfg *Config) error {
	arg := make([](*C.char), 0)
	for _, s := range cfg.NextProtos {
		cbuf := C.CString(s)
		defer C.free(unsafe.Pointer(cbuf))
		arg = append(arg, (*C.char)(cbuf))
	}
	ret := C.alpn_set_protocols(sess,
		(**C.char)(unsafe.Pointer(&arg[0])), C.int(len(cfg.NextProtos)))
	if int(ret) < 0 {
		return fmt.Errorf("set alpn failed: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	return nil

}

// Handshake call handshake for TLS Conn,
// this function will call automatic on Read/Write, if not handshake yet
func (c *Conn) Handshake() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.handshake {
		return nil
	}
	ret := C.handshake(c.sess)
	if int(ret) < 0 {
		return fmt.Errorf("handshake error: %s", C.GoString(C.gnutls_strerror(ret)))
	}
	c.handshake = true
	//log.Println("handshake done")
	return nil
}

// Read read application data from TLS connection
func (c *Conn) Read(buf []byte) (n int, err error) {
	err = c.Handshake()
	if err != nil {
		return
	}

	if len(buf) == 0 {
		return 0, nil
	}

	//bufLen := len(buf)
	//cbuf := C.malloc(C.size_t(bufLen))
	//defer C.free(cbuf)

	ret := C.gnutls_record_recv(c.sess.session,
		unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if int(ret) < 0 {
		return 0, fmt.Errorf("read error: %s",
			C.GoString(C.gnutls_strerror(C.int(ret))))
	}

	if int(ret) == 0 {
		return 0, io.EOF
	}

	n = int(ret)
	//gobuf2 := C.GoBytes(cbuf, C.int(ret))
	//copy(buf, gobuf2)
	return n, nil
}

// Write write application data to TLS connection
func (c *Conn) Write(buf []byte) (n int, err error) {
	err = c.Handshake()
	if err != nil {
		return
	}

	// user may call Write(nil) to do handshake
	if len(buf) == 0 {
		return 0, nil
	}

	//cbuf := C.CBytes(buf)
	//defer C.free(cbuf)

	ret := C.gnutls_record_send(c.sess.session,
		unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	n = int(ret)

	if n < 0 {
		return 0, fmt.Errorf("write error: %s",
			C.GoString(C.gnutls_strerror(C.int(ret))))
	}

	if int(ret) == 0 {
		return 0, io.EOF
	}

	return n, nil
}

// Close close the TLS conn and destroy the tls context
func (c *Conn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.closed {
		return nil
	}
	C.gnutls_record_send(c.sess.session, nil, 0)
	C.session_destroy(c.sess)
	c.c.Close()
	if c.cservname != nil {
		C.free(unsafe.Pointer(c.cservname))
	}

	if c.state != nil && c.state.PeerCertificate != nil {
		c.state.PeerCertificate.Free()
	}
	c.closed = true
	return nil
}

func (c *Conn) free() {
	//log.Println("free conn")
	c.Close()
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

// ConnectionState get TLS connection state
func (c *Conn) ConnectionState() *ConnectionState {
	if c.state != nil {
		return c.state
	}
	version :=
		uint16(C.gnutls_protocol_get_version(c.sess.session))

	versionname := C.GoString(
		C.gnutls_protocol_get_name(C.gnutls_protocol_t(version)))

	state := &ConnectionState{
		NegotiatedProtocol: c.getAlpnSelectedProtocol(),
		Version:            version,
		HandshakeComplete:  c.handshake,
		ServerName:         c.getServerName(),
		VersionName:        versionname,
		PeerCertificate:    c.getPeerCertificate(),
	}
	c.state = state
	return state
}

func (c *Conn) getPeerCertificate() *Certificate {
	var size int
	st := C.get_peer_certificate(c.sess.session, (*C.int)(unsafe.Pointer(&size)))
	if st == nil {
		return nil
	}
	cert := &Certificate{cert: st, certSize: C.int(size)}
	runtime.SetFinalizer(cert, (*Certificate).free)
	return cert
}

func (c *Conn) getAlpnSelectedProtocol() string {
	cbuf := C.malloc(100)
	defer C.free(cbuf)

	ret := C.alpn_get_selected_protocol(c.sess, (*C.char)(cbuf))
	if int(ret) < 0 {
		return ""
	}
	alpnname := C.GoString((*C.char)(cbuf))
	return alpnname
}

func (c *Conn) getServerName() string {
	buflen := 100
	nametype := GNUTLS_NAME_DNS
	cbuf := C.malloc(C.size_t(buflen))
	defer C.free(cbuf)

	ret := C.gnutls_server_name_get(c.sess.session, cbuf,
		(*C.size_t)(unsafe.Pointer(&buflen)),
		(*C.uint)(unsafe.Pointer(&nametype)), 0)
	if int(ret) < 0 {
		return ""
	}
	name := C.GoString((*C.char)(cbuf))
	return name
}

// onDataReadCallback callback function for gnutls library want to read data from network
//
//export onDataReadCallback
func onDataReadCallback(d unsafe.Pointer, cbuf *C.char, bufLen C.int) C.int {
	//log.Println("read addr ", uintptr(d))
	conn := (*Conn)(unsafe.Pointer((uintptr(d))))
	buf := make([]byte, int(bufLen))
	n, err := conn.c.Read(buf)
	if err != nil {
		log.Println(err)
		return -1
	}
	//cbuf2 := C.CBytes(buf[:n])
	// d := C.CString(string(buf[:n]))
	//defer C.free(cbuf2)
	C.memcpy(unsafe.Pointer(cbuf), unsafe.Pointer(&buf[0]), C.size_t(n))
	return C.int(n)
}

// onDataWriteCallback callback function for gnutls library want to send data to network
//
//export onDataWriteCallback
func onDataWriteCallback(d unsafe.Pointer, cbuf *C.char, bufLen C.int) C.int {
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

// onDataTimeoutRead callback function for timeout read
//
//export onDataTimeoutRead
func onDataTimeoutRead(d unsafe.Pointer, delay C.int) C.int {
	log.Println("timeout pull function")
	return 0
}

// onCertSelectCallback callback function for ceritificate select,
// this function select certificate from Config.Certificates field,
//
// on server side, this function select the certificate depend on SNI what client send,
// if client not send SNI, select the Config.Certificates[0]
//
//export onCertSelectCallback
func onCertSelectCallback(ptr unsafe.Pointer, hostname *C.char,
	namelen C.int, pcertLength *C.int, cert **C.gnutls_pcert_st, privkey *C.gnutls_privkey_t) C.int {

	servername := C.GoStringN(hostname, namelen)
	//log.Println("go cert select callback ", servername)
	conn := (*Conn)(unsafe.Pointer((uintptr(ptr))))
	//log.Println(conn)
	if int(namelen) == 0 && conn.cfg.Certificates != nil {
		_cert := conn.cfg.Certificates[0]
		*pcertLength = _cert.certSize
		*cert = _cert.cert
		*privkey = _cert.privkey
		//log.Println("set pcert length ", _cert.certSize)
		return 0
	}
	for _, _cert := range conn.cfg.Certificates {
		//log.Println(cert)
		if _cert.matchName(servername) {
			//log.Println("matched name ", _cert.names)
			*pcertLength = _cert.certSize
			*cert = _cert.cert
			*privkey = _cert.privkey
			//log.Println("set pcert length ", _cert.certSize)
			return 0
		}
	}
	if conn.cfg.Certificates != nil {
		_cert := conn.cfg.Certificates[0]
		*pcertLength = _cert.certSize
		*cert = _cert.cert
		*privkey = _cert.privkey
		//log.Println("set pcert length ", _cert.certSize)
		return 0
	}
	*pcertLength = 0
	//log.Println("set pcert length 0")
	return -1
}
