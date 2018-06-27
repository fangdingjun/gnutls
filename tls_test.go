package gnutls

import (
	"crypto/tls"
	"log"
	"net"
	"testing"
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

	c, err := Dial("tcp", addr, &Config{})
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
	l, err := Listen("tcp", "127.0.0.1:0", &Config{
		CrtFile: "testdata/server.crt", KeyFile: "testdata/server.key"})
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
}
