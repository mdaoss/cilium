package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	connTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "egw_test_connections_total",
		Help: "Total accepted connections",
	})
	connActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "egw_test_connections_active",
		Help: "Currently active connections",
	})
	connRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "egw_test_requests_received_total",
		Help: "Total requests received (connections that sent data)",
	})
)

var count atomic.Int64

func handleConn(conn net.Conn) {
	connActive.Inc()
	defer func() {
		conn.Close()
		connActive.Dec()
	}()
	n := count.Add(1)
	connTotal.Inc()
	buf := make([]byte, 256)
	nr, _ := conn.Read(buf)
	if nr > 0 {
		connRequests.Inc()
	}
	if n%100 == 0 {
		fmt.Fprintf(os.Stderr, "connections: %d\n", n)
	}
}

func main() {
	addr := flag.String("addr", ":9999", "listen address (e.g. :9999 or :9999,:9998)")
	metricsAddr := flag.String("metrics", ":9090", "prometheus metrics address")
	flag.Parse()

	prometheus.MustRegister(connTotal, connActive, connRequests)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Fprintf(os.Stderr, "metrics on %s/metrics\n", *metricsAddr)
		log.Fatal(http.ListenAndServe(*metricsAddr, nil))
	}()

	addrs := strings.Split(*addr, ",")
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "listening on %s\n", a)
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					log.Println("accept error:", err)
					continue
				}
				go handleConn(conn)
			}
		}(ln)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintf(os.Stderr, "\ntotal connections: %d\n", count.Load())
}
