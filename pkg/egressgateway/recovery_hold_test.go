// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestRegenerateGatewayConfigSkipsRecoveredGatewayInHold(t *testing.T) {
	mgr := &Manager{
		nodes: []nodeTypes.Node{
			{
				Name:   "gw0",
				Labels: map[string]string{"egress-gateway": "true"},
				IPAddresses: []nodeTypes.Address{
					{Type: addressing.NodeInternalIP, IP: netip.MustParseAddr("100.64.0.128").AsSlice()},
				},
			},
			{
				Name:   "gw1",
				Labels: map[string]string{"egress-gateway": "true"},
				IPAddresses: []nodeTypes.Address{
					{Type: addressing.NodeInternalIP, IP: netip.MustParseAddr("100.64.0.130").AsSlice()},
				},
			},
		},
		unhealthyGateways: make(map[string]struct{}),
		recoveredGatewayHoldUntil: map[string]time.Time{
			"gw1": time.Now().Add(time.Minute),
		},
		recoveredGatewayTimers: make(map[string]*time.Timer),
	}

	cfg := &PolicyConfig{
		policyGwConfig: &policyGatewayConfig{
			nodeSelector: api.NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"egress-gateway": "true"},
			}),
			egressIP: netip.MustParseAddr("100.64.0.200"),
		},
	}

	cfg.regenerateGatewayConfig(mgr)

	// gw0 in slot 0, gw1 in slot 1 (always preserved), but only gw0 active
	require.Equal(t, netip.MustParseAddr("100.64.0.128"), cfg.gatewayConfig.gatewayIP)
	require.Equal(t, netip.MustParseAddr("100.64.0.130"), cfg.gatewayConfig.gatewayIP1)
	require.Equal(t, egressmap.ActiveGW0, cfg.gatewayConfig.activeGW)
}

func TestRegenerateGatewayConfigReenablesGatewayAfterHoldExpires(t *testing.T) {
	mgr := &Manager{
		nodes: []nodeTypes.Node{
			{
				Name:   "gw0",
				Labels: map[string]string{"egress-gateway": "true"},
				IPAddresses: []nodeTypes.Address{
					{Type: addressing.NodeInternalIP, IP: netip.MustParseAddr("100.64.0.128").AsSlice()},
				},
			},
			{
				Name:   "gw1",
				Labels: map[string]string{"egress-gateway": "true"},
				IPAddresses: []nodeTypes.Address{
					{Type: addressing.NodeInternalIP, IP: netip.MustParseAddr("100.64.0.130").AsSlice()},
				},
			},
		},
		unhealthyGateways: make(map[string]struct{}),
		recoveredGatewayHoldUntil: map[string]time.Time{
			"gw1": time.Now().Add(-time.Second),
		},
		recoveredGatewayTimers: make(map[string]*time.Timer),
	}

	cfg := &PolicyConfig{
		policyGwConfig: &policyGatewayConfig{
			nodeSelector: api.NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"egress-gateway": "true"},
			}),
			egressIP: netip.MustParseAddr("100.64.0.200"),
		},
	}

	cfg.regenerateGatewayConfig(mgr)

	require.Equal(t, netip.MustParseAddr("100.64.0.128"), cfg.gatewayConfig.gatewayIP)
	require.Equal(t, netip.MustParseAddr("100.64.0.130"), cfg.gatewayConfig.gatewayIP1)
	require.Equal(t, egressmap.ActiveGWBoth, cfg.gatewayConfig.activeGW)
	_, held := mgr.recoveredGatewayHoldUntil["gw1"]
	require.False(t, held)
}
