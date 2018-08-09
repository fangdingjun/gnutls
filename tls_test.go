package gnutls

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func TestTLSClient(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal("load certificate failed")
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal("listen failed")
	}
	defer l.Close()
	addr := l.Addr().String()
	t.Log("test server listen on ", addr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}
			t.Logf("accept connection from %s", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				for {
					buf := make([]byte, 4096)
					n, err := c.Read(buf)
					if err != nil {
						t.Log("connection closed")
						break
					}
					if _, err = c.Write(buf[:n]); err != nil {
						break
					}
				}
			}(c)
		}
	}()

	c, err := Dial("tcp", addr, &Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("gnutls dial ", err)
	}
	defer c.Close()

	data := "hello, world"
	if _, err = c.Write([]byte(data)); err != nil {
		t.Fatal("gnutls write ", err)
	}
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("gnutls read ", err)
	}
	if string(buf[:n]) != data {
		t.Errorf("need: %s, got: %s", data, string(buf[:n]))
	}
}

func TestTLSServer(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("tcp", "127.0.0.1:0", &Config{
		Certificates: []*Certificate{cert},
	})
	if err != nil {
		t.Fatal("gnutls listen ", err)
	}
	addr := l.Addr().String()
	t.Log("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Log("gnutls accept ", err)
				break
			}
			t.Log("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsconn := c.(*Conn)
				if err := tlsconn.Handshake(); err != nil {
					t.Log(err)
					return
				}
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						t.Log("gnutls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						t.Log("gnutls write ", err)
						break
					}
				}
			}(c)
		}
	}()

	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("dial ", err)
	}
	defer c.Close()

	data := "hello, world"
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatal("write ", err)
	}
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("read ", err)
	}
	if string(buf[:n]) != data {
		t.Errorf("need: %s, got: %s", data, string(buf[:n]))
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func TestTLSALPNServer(t *testing.T) {
	serveralpn := []string{"a1", "a3", "a2"}
	clientalpn := []string{"a0", "a2", "a5"}
	expectedAlpn := "a2"
	cert, err := LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("tcp", "127.0.0.1:0", &Config{
		Certificates: []*Certificate{cert},
		NextProtos:   serveralpn,
	})
	if err != nil {
		t.Fatal("gnutls listen ", err)
	}
	addr := l.Addr().String()
	t.Log("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Log("gnutls accept ", err)
				break
			}
			t.Log("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*Conn)
				if err := tlsConn.Handshake(); err != nil {
					t.Log(err)
					return
				}
				connState := tlsConn.ConnectionState()
				t.Logf("%+v", connState)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						t.Log("gnutls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						t.Log("gnutls write ", err)
						break
					}
				}
			}(c)
		}
	}()

	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         clientalpn,
	})
	if err != nil {
		t.Fatal("dial ", err)
	}
	defer c.Close()

	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	connState := c.ConnectionState()
	t.Logf("%+v", connState)

	if connState.NegotiatedProtocol != expectedAlpn {
		t.Errorf("expected alpn %s, got %s",
			expectedAlpn, connState.NegotiatedProtocol)
	}

	data := "hello, world"
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatal("write ", err)
	}
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("read ", err)
	}
	if string(buf[:n]) != data {
		t.Errorf("need: %s, got: %s", data, string(buf[:n]))
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func TestTLSALPNClient(t *testing.T) {
	serveralpn := []string{"a1", "a3", "a2"}
	clientalpn := []string{"a0", "a2", "a5"}
	expectedAlpn := "a2"

	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal("load key failed")
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   serveralpn,
	})

	if err != nil {
		t.Fatal("tls listen ", err)
	}
	addr := l.Addr().String()
	t.Log("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Log("gnutls accept ", err)
				break
			}
			t.Log("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					t.Log(err)
					return
				}
				connState := tlsConn.ConnectionState()
				t.Logf("%+v", connState)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						t.Log("tls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						t.Log("tls write ", err)
						break
					}
				}
			}(c)
		}
	}()

	c, err := Dial("tcp", addr, &Config{InsecureSkipVerify: true,
		ServerName: "localhost",
		NextProtos: clientalpn,
	})
	if err != nil {
		t.Fatal("dial ", err)
	}
	defer c.Close()

	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	connState := c.ConnectionState()
	t.Logf("%+v", connState)

	if connState.NegotiatedProtocol != expectedAlpn {
		t.Errorf("expected alpn %s, got %s",
			expectedAlpn, connState.NegotiatedProtocol)
	}

	data := "hello, world"
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatal("write ", err)
	}
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("read ", err)
	}
	if string(buf[:n]) != data {
		t.Errorf("need: %s, got: %s", data, string(buf[:n]))
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func TestTLSServerSNI(t *testing.T) {
	certificates := []*Certificate{}
	cert, err := LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal("load key failed")
	}

	certificates = append(certificates, cert)
	cert, err = LoadX509KeyPair("testdata/server2.crt", "testdata/server2.key")
	if err != nil {
		t.Fatal("load key failed")
	}

	certificates = append(certificates, cert)
	cert, err = LoadX509KeyPair("testdata/server3.crt", "testdata/server3.key")
	if err != nil {
		t.Fatal("load key failed")
	}
	certificates = append(certificates, cert)

	l, err := Listen("tcp", "127.0.0.1:0", &Config{
		Certificates: certificates,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				t.Log(err)
				break
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsconn := c.(*Conn)
				if err := tlsconn.Handshake(); err != nil {
					t.Log(err)
					return
				}
				state := tlsconn.ConnectionState()
				fmt.Fprintf(c, state.ServerName)
			}(c)
		}
	}()

	for _, cfg := range []struct {
		serverName string
		commonName string
	}{
		{"abc.com", "abc.com"},
		{"example.com", "example.com"},
		{"a.aaa.com", "*.aaa.com"},
		{"b.aaa.com", "*.aaa.com"},
	} {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName:         cfg.serverName,
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		state := conn.ConnectionState()
		_commonName := state.PeerCertificates[0].Subject.CommonName
		if _commonName != cfg.commonName {
			t.Errorf("expect: %s, got: %s", cfg.commonName, _commonName)
		}
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Error(err)
		}
		if !bytes.Equal(buf[:n], []byte(cfg.serverName)) {
			t.Errorf("expect %s, got %s", cfg.serverName, string(buf[:n]))
		}
		conn.Close()
	}
	runtime.GC()
	time.Sleep(1 * time.Second)
}

func TestTLSGetPeerCert(t *testing.T) {
	conn, err := Dial("tcp", "www.ratafee.nl:443", &Config{
		ServerName: "www.ratafee.nl",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	//tlsconn := conn.(*Conn)
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	for i := 0; i < int(state.PeerCertificate.certSize); i++ {
		t.Log(state.PeerCertificate.getCertString(i, 1))
	}

	req, _ := http.NewRequest("GET", "https://www.ratafee.nl/httpbin/ip", nil)
	req.Write(conn)
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		t.Error(err)
	}
	var buf = new(bytes.Buffer)
	resp.Write(buf)
	t.Logf("%s", string(buf.Bytes()))
	runtime.GC()
	time.Sleep(1 * time.Second)
}
