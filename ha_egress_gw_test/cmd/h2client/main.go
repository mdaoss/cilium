package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	server := flag.String("server", "https://100.64.0.129:9998", "server URL (https)")
	total := flag.Int("total", 200, "total requests (0 = use duration+rps)")
	parallel := flag.Int("parallel", 500, "max concurrent in-flight requests")
	conns := flag.Int("conns", 50, "number of HTTP/2 connections")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	rps := flag.Int("rps", 0, "target requests per second (0 = unlimited)")
	duration := flag.Duration("duration", 0, "test duration (e.g. 5m); requires -rps")
	reportInterval := flag.Duration("report", 5*time.Second, "progress report interval")
	flag.Parse()

	targetTotal := *total
	if *duration > 0 && *rps > 0 {
		targetTotal = int(duration.Seconds()) * *rps
		fmt.Fprintf(os.Stderr, "Duration mode: %v at %d rps = %d total requests\n",
			*duration, *rps, targetTotal)
	}

	numConns := *conns
	if numConns < 1 {
		numConns = 1
	}

	// Create N HTTP clients, each with its own transport = own TCP/TLS/HTTP2 connection.
	clients := make([]*http.Client, numConns)
	for i := range clients {
		clients[i] = &http.Client{
			Timeout: *timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 1,
				MaxConnsPerHost:     1,
			},
		}
	}

	var ok, fail atomic.Int64
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup

	start := time.Now()
	lastReport := start
	var lastOk, lastFail int64

	var ticker *time.Ticker
	if *rps > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(*rps))
		defer ticker.Stop()
	}

	done := make(chan struct{})
	if *reportInterval > 0 {
		go func() {
			t := time.NewTicker(*reportInterval)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					elapsed := time.Since(start)
					curOk := ok.Load()
					curFail := fail.Load()
					intervalOk := curOk - lastOk
					intervalFail := curFail - lastFail
					intervalElapsed := time.Since(lastReport)
					actualRPS := float64(intervalOk+intervalFail) / intervalElapsed.Seconds()
					fmt.Fprintf(os.Stderr, "[%v] %d/%d (ok=%d fail=%d) %.0f rps\n",
						elapsed.Round(time.Second), curOk+curFail, targetTotal,
						curOk, curFail, actualRPS)
					lastOk = curOk
					lastFail = curFail
					lastReport = time.Now()
				}
			}
		}()
	}

	for i := 0; i < targetTotal; i++ {
		if ticker != nil {
			<-ticker.C
		}
		wg.Add(1)
		sem <- struct{}{}
		client := clients[i%numConns]
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := client.Get(*server)
			if err != nil {
				fail.Add(1)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ok.Add(1)
			} else {
				fail.Add(1)
			}
		}()
	}
	wg.Wait()
	close(done)

	elapsed := time.Since(start)
	totalDone := ok.Load() + fail.Load()
	fmt.Printf("DONE: %d ok, %d fail out of %d in %v (%.0f avg rps)\n",
		ok.Load(), fail.Load(), targetTotal, elapsed.Round(time.Second),
		float64(totalDone)/elapsed.Seconds())
}
