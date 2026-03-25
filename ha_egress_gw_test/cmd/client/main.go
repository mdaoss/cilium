package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	server := flag.String("server", "100.64.0.129:9999", "server address")
	total := flag.Int("total", 200, "total connections (0 = use duration+rps)")
	parallel := flag.Int("parallel", 100, "max concurrent connections")
	timeout := flag.Duration("timeout", 5*time.Second, "connect timeout")
	rps := flag.Int("rps", 0, "target requests per second (0 = unlimited)")
	duration := flag.Duration("duration", 0, "test duration (e.g. 15m); requires -rps")
	reportInterval := flag.Duration("report", 5*time.Second, "progress report interval")
	flag.Parse()

	// Compute total from duration+rps if specified
	targetTotal := *total
	if *duration > 0 && *rps > 0 {
		targetTotal = int(duration.Seconds()) * *rps
		fmt.Fprintf(os.Stderr, "Duration mode: %v at %d rps = %d total connections\n",
			*duration, *rps, targetTotal)
	}

	var ok, fail atomic.Int64
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup

	start := time.Now()
	lastReport := start
	var lastOk, lastFail int64

	// Rate limiter: if rps > 0, use a ticker
	var ticker *time.Ticker
	if *rps > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(*rps))
		defer ticker.Stop()
	}

	// Progress reporter
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
		go func(seq int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", *server, *timeout)
			if err != nil {
				fail.Add(1)
				return
			}
			fmt.Fprintf(conn, "C-%d\n", seq)
			conn.Close()
			ok.Add(1)
		}(i)
	}
	wg.Wait()
	close(done)

	elapsed := time.Since(start)
	totalDone := ok.Load() + fail.Load()
	fmt.Printf("DONE: %d ok, %d fail out of %d in %v (%.0f avg rps)\n",
		ok.Load(), fail.Load(), targetTotal, elapsed.Round(time.Second),
		float64(totalDone)/elapsed.Seconds())
}
