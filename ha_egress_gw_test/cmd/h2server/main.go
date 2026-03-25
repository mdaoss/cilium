package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

var reqCount atomic.Int64

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4zero},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func main() {
	addr := flag.String("addr", ":9998", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		if n%1000 == 0 {
			fmt.Fprintf(os.Stderr, "requests: %d\n", n)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert()},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", *addr, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "HTTP/2 (TLS) server listening on %s\n", *addr)

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintf(os.Stderr, "\ntotal requests: %d\n", reqCount.Load())
}
