// Package gnutls is a gnutls binding for golang.
/*
a limit set of api is supported.

TLS api is very similar to crypto/tls on standard library.

TLS client example:

	addr := "127.0.0.1:9443"
	c, err := gnutls.Dial("tcp", addr, &gnutls.Config{ServerName: "localhost",InsecureSkipVerify: true})
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

TLS Server example:
	cert, err := gnutls.LoadX509KeyPair("testdata/server/crt", "testdata/server.key")
	if err != nil{
		// handle error
	}
	l, err := gnults.Listen("tcp", "127.0.0.1:9443", &gnutls.Config{
		Certificates: []*gnutls.Certificate{cert}})
	if err != nil {
		// handle error
	}
	defer l.Close()
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

AES encrypt/decrypt example:

	key := []byte("0123456789abcdef")
	iv := []byte("abcdefg123456789")
	c, err := gnutls.NewCipher(gnutls.GNUTLS_CIPHER_AES_128_CBC, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c1, err := gnutls.NewCipher(gnutls.GNUTLS_CIPHER_AES_128_CBC, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	data := []byte("1234012121212121")
	if c == nil {
		t.Fatal("new ciphoer failed")
	}

	// encrypt
	dst := make([]byte, len(data))
	err := c.Encrypt(dst, data)
	if err != nil {
		t.Fatal("encrypt failed", err)
	}

	// decrypt
	data1 := make([]byte, len(data))
	err := c1.Decrypt(data1, cdata)
	if err != nil {
		t.Fatal("decrypt failed", err)
	}


Hash example:

	h := gnutls.NewHash(gnutls.GNUTLS_HASH_SHA512)
	defer h.Close()

	data := []byte("1234")

	h1 := h.Sum(data)

*/
package gnutls
