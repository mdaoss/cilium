// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.Nil(t, rlimit.RemoveMemlock())

	egressPolicyMap := createPolicyMap(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

	sourceIP1 := netip.MustParseAddr("1.1.1.1")
	sourceIP2 := netip.MustParseAddr("1.1.1.2")

	destCIDR1 := netip.MustParsePrefix("2.2.1.0/24")
	destCIDR2 := netip.MustParsePrefix("2.2.2.0/24")

	egressIP1 := netip.MustParseAddr("3.3.3.1")
	egressIP2 := netip.MustParseAddr("3.3.3.2")

	gatewayA := netip.MustParseAddr("4.4.4.1")
	gatewayB := netip.MustParseAddr("4.4.4.2")

	err := egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, gatewayA, gatewayB, ActiveGWBoth)
	assert.Nil(t, err)

	err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, gatewayA, netip.IPv4Unspecified(), ActiveGW0)
	assert.Nil(t, err)

	val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)

	assert.Equal(t, val.EgressIP.Addr(), egressIP1)
	assert.Equal(t, val.GatewayIP0.Addr(), gatewayA)
	assert.Equal(t, val.GatewayIP1.Addr(), gatewayB)

	val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
	assert.Nil(t, err)

	assert.Equal(t, val.EgressIP.Addr(), egressIP2)
	assert.Equal(t, val.GatewayIP0.Addr(), gatewayA)
	assert.Equal(t, val.GatewayIP1.Addr(), netip.IPv4Unspecified())

	err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
	assert.Nil(t, err)

	val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)

	assert.Equal(t, val.EgressIP.Addr(), egressIP1)
	assert.Equal(t, val.GatewayIP0.Addr(), gatewayA)
	assert.Equal(t, val.GatewayIP1.Addr(), gatewayB)

	_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
	assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist))
}
