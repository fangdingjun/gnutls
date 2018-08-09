package gnutls

import (
	"runtime"
	"testing"
	"time"
)

func TestGetAltname(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", cert)
	t.Log(cert.GetAltName())
	t.Log(cert.GetCertString())
	t.Log(cert.GetDN())
	t.Log(cert.GetIssuerDN())
	t.Log("CN ", cert.CommonName())
	//t.Log("flag 0: ", cert.getCertString(0, 0))
	//t.Log("flag 1: ", cert.getCertString(0, 1))
	//t.Log("flag 2: ", cert.getCertString(0, 2))
	//t.Log("flag 3: ", cert.getCertString(0, 3))
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
