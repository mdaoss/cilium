// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// defaultProbeTimeout is the TCP connect timeout for each probe.
	defaultProbeTimeout = 1 * time.Second

	// defaultFailureThreshold is how many consecutive failures before
	// marking a gateway unhealthy.
	defaultFailureThreshold = 3

	// defaultRecoveryThreshold is how many consecutive successes before
	// marking a previously-unhealthy gateway as recovered. Must be high
	// enough for the recovered Cilium agent to fully compile and load
	// BPF programs. After the health port comes up, the agent may
	// trigger a "devices changed" BPF recompilation (~18s) followed by
	// program reload (~10s). Total observed: ~35s from first probe to
	// final overlay BPF attachment. 40 probes at 1s provides margin.
	defaultRecoveryThreshold = 40

	// ciliumHealthPort is the Cilium agent health API port used for probes.
	ciliumHealthPort = 4240
)

// gatewayHealthEvent represents a change in gateway node health status.
type gatewayHealthEvent struct {
	nodeName string
	healthy  bool
}

// gatewayTarget represents a remote gateway node to probe.
type gatewayTarget struct {
	name string
	ip   netip.Addr
}

// gatewayProber periodically checks the health of remote gateway nodes by
// attempting TCP connections to the Cilium agent health port (4240). When a
// gateway becomes unreachable after consecutive failures, it notifies the
// egress gateway manager so the policy map can be updated to exclude the
// dead gateway.
type gatewayProber struct {
	mu                sync.Mutex
	targets           []gatewayTarget
	failureCounts     map[string]int
	recoveryCounts    map[string]int
	unhealthy         map[string]struct{}
	healthCh          chan<- gatewayHealthEvent
	probeInterval     time.Duration
	probeTimeout      time.Duration
	failureThreshold  int
	recoveryThreshold int
}

func newGatewayProber(healthCh chan<- gatewayHealthEvent, probeInterval time.Duration, probeTimeout time.Duration, recoveryThreshold int) *gatewayProber {
	if recoveryThreshold <= 0 {
		recoveryThreshold = defaultRecoveryThreshold
	}
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	return &gatewayProber{
		failureCounts:     make(map[string]int),
		recoveryCounts:    make(map[string]int),
		unhealthy:         make(map[string]struct{}),
		healthCh:          healthCh,
		probeInterval:     probeInterval,
		probeTimeout:      probeTimeout,
		failureThreshold:  defaultFailureThreshold,
		recoveryThreshold: recoveryThreshold,
	}
}

// setTargets updates the list of remote gateway nodes to probe.
// Called by the manager after each reconciliation.
func (p *gatewayProber) setTargets(targets []gatewayTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.targets = make([]gatewayTarget, len(targets))
	copy(p.targets, targets)

	// Clean up state for nodes no longer targeted.
	activeNames := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		activeNames[t.name] = struct{}{}
	}
	for name := range p.failureCounts {
		if _, ok := activeNames[name]; !ok {
			delete(p.failureCounts, name)
		}
	}
	for name := range p.unhealthy {
		if _, ok := activeNames[name]; !ok {
			delete(p.unhealthy, name)
		}
	}
	for name := range p.recoveryCounts {
		if _, ok := activeNames[name]; !ok {
			delete(p.recoveryCounts, name)
		}
	}
}

// run starts the probing loop. Blocks until ctx is cancelled.
func (p *gatewayProber) run(ctx context.Context) {
	ticker := time.NewTicker(p.probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll(ctx)
		}
	}
}

func (p *gatewayProber) probeAll(ctx context.Context) {
	p.mu.Lock()
	targets := make([]gatewayTarget, len(p.targets))
	copy(targets, p.targets)
	p.mu.Unlock()

	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}

		healthy := p.probeNode(target)
		p.handleProbeResult(target, healthy)
	}
}

func (p *gatewayProber) probeNode(target gatewayTarget) bool {
	addr := net.JoinHostPort(target.ip.String(), fmt.Sprintf("%d", ciliumHealthPort))
	conn, err := net.DialTimeout("tcp", addr, p.probeTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (p *gatewayProber) handleProbeResult(target gatewayTarget, healthy bool) {
	// Determine the event to send (if any) while holding the lock,
	// then release the lock before sending on the channel. This avoids
	// a deadlock where the prober holds p.mu waiting on a full channel
	// while the manager holds its Mutex (blocking processEvents from
	// draining the channel) and tries to acquire p.mu via setTargets.
	var event *gatewayHealthEvent

	p.mu.Lock()
	_, wasUnhealthy := p.unhealthy[target.name]

	if healthy {
		p.failureCounts[target.name] = 0
		if wasUnhealthy {
			p.recoveryCounts[target.name]++
			count := p.recoveryCounts[target.name]
			if count >= p.recoveryThreshold {
				delete(p.unhealthy, target.name)
				delete(p.recoveryCounts, target.name)
				event = &gatewayHealthEvent{nodeName: target.name, healthy: true}
			}
		}
	} else {
		p.failureCounts[target.name]++
		// Reset recovery progress on any failure.
		delete(p.recoveryCounts, target.name)
		count := p.failureCounts[target.name]
		if !wasUnhealthy && count >= p.failureThreshold {
			p.unhealthy[target.name] = struct{}{}
			event = &gatewayHealthEvent{nodeName: target.name, healthy: false}
		}
	}
	p.mu.Unlock()

	if event != nil {
		if event.healthy {
			log.WithField(logfields.NodeName, target.name).
				Info("Gateway node recovered, restoring to egress policy")
		} else {
			log.WithField(logfields.NodeName, target.name).
				Warn("Gateway node unreachable, removing from egress policy")
		}
		p.healthCh <- *event
	} else if healthy && wasUnhealthy {
		// Log recovery progress (event is nil because threshold not yet reached).
		p.mu.Lock()
		count := p.recoveryCounts[target.name]
		p.mu.Unlock()
		log.WithField(logfields.NodeName, target.name).
			Infof("Gateway node recovery probe %d/%d", count, p.recoveryThreshold)
	}
}
