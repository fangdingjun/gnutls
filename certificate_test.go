package gnutls

import (
	"log"
	"runtime"
	"testing"
	"time"
)

func TestGetAltname(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%+v", cert)
	log.Println(cert.GetAltName())
	log.Println(cert.GetCertString())
	log.Println(cert.GetDN())
	log.Println(cert.GetIssuerDN())
	log.Println("CN ", cert.CommonName())
	//log.Println("flag 0: ", cert.getCertString(0, 0))
	//log.Println("flag 1: ", cert.getCertString(0, 1))
	//log.Println("flag 2: ", cert.getCertString(0, 2))
	//log.Println("flag 3: ", cert.getCertString(0, 3))
	cert.Free()
}

func _loadCert(certfile, keyfile string) (*Certificate, error) {
	return LoadX509KeyPair(certfile, keyfile)
}

func TestCertGC(t *testing.T) {
	_loadCert("testdata/server.crt", "testdata/server.key")
	runtime.GC()
	time.Sleep(1 * time.Second)
}
