package gnutls

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	log.Println("test server listen on ", addr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}
			log.Printf("accept connection from %s", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				for {
					buf := make([]byte, 4096)
					n, err := c.Read(buf)
					if err != nil {
						log.Println("connection closed")
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
	log.Println("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Println("gnutls accept ", err)
				break
			}
			log.Println("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsconn := c.(*Conn)
				if err := tlsconn.Handshake(); err != nil {
					log.Println(err)
					return
				}
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						log.Println("gnutls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						log.Println("gnutls write ", err)
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
	log.Println("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Println("gnutls accept ", err)
				break
			}
			log.Println("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*Conn)
				if err := tlsConn.Handshake(); err != nil {
					log.Println(err)
					return
				}
				connState := tlsConn.ConnectionState()
				log.Printf("%+v", connState)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						log.Println("gnutls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						log.Println("gnutls write ", err)
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
	log.Printf("%+v", connState)

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
	log.Println("test server listen on ", addr)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Println("gnutls accept ", err)
				break
			}
			log.Println("accept connection from ", c.RemoteAddr())
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					log.Println(err)
					return
				}
				connState := tlsConn.ConnectionState()
				log.Printf("%+v", connState)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf[0:])
					if err != nil {
						log.Println("tls read ", err)
						break
					}
					if _, err := c.Write(buf[:n]); err != nil {
						log.Println("tls write ", err)
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
	log.Printf("%+v", connState)

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
				log.Println(err)
				break
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsconn := c.(*Conn)
				if err := tlsconn.Handshake(); err != nil {
					log.Println(err)
					return
				}
				state := tlsconn.ConnectionState()
				fmt.Fprintf(c, state.ServerName)
			}(c)
		}
	}()

	for _, servername := range []string{"abc.com", "example.com", "a.aaa.com", "b.aaa.com"} {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName:         servername,
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		//state := conn.ConnectionState()
		//log.Printf("%+v", state.PeerCertificates[0])
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Error(err)
		}
		if !bytes.Equal(buf[:n], []byte(servername)) {
			t.Errorf("expect %s, got %s", servername, string(buf[:n]))
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
		log.Println(state.PeerCertificate.getCertString(i, 1))
	}

	req, _ := http.NewRequest("GET", "https://www.ratafee.nl/httpbin/ip", nil)
	req.Write(conn)
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		t.Error(err)
	}
	resp.Write(os.Stdout)
	runtime.GC()
	time.Sleep(1 * time.Second)
}
