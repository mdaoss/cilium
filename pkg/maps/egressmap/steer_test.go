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

func TestSteerMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.Nil(t, rlimit.RemoveMemlock())

	steerMap := CreatePrivateSteerMap(hivetest.Lifecycle(t))

	key1 := EgressSteerKey4{
		NextHdr: 6, // TCP
	}
	key1.SAddr.FromAddr(netip.MustParseAddr("10.0.0.1"))
	key1.DAddr.FromAddr(netip.MustParseAddr("192.168.1.1"))
	key1.SPort = 80
	key1.DPort = 32768

	val1 := EgressSteerVal4{
		OwnerIdx: 0,
	}
	val1.OwnerIP.FromAddr(netip.MustParseAddr("4.4.4.1"))

	key2 := EgressSteerKey4{
		NextHdr: 17, // UDP
	}
	key2.SAddr.FromAddr(netip.MustParseAddr("10.0.0.2"))
	key2.DAddr.FromAddr(netip.MustParseAddr("192.168.1.2"))
	key2.SPort = 443
	key2.DPort = 38302

	val2 := EgressSteerVal4{
		OwnerIdx: 1,
	}
	val2.OwnerIP.FromAddr(netip.MustParseAddr("4.4.4.2"))

	// Insert two entries
	err := steerMap.Update(&key1, &val1)
	assert.Nil(t, err)

	err = steerMap.Update(&key2, &val2)
	assert.Nil(t, err)

	// Lookup first entry
	got, err := steerMap.Lookup(&key1)
	assert.Nil(t, err)
	assert.Equal(t, val1.OwnerIP, got.OwnerIP)
	assert.Equal(t, val1.OwnerIdx, got.OwnerIdx)

	// Lookup second entry
	got, err = steerMap.Lookup(&key2)
	assert.Nil(t, err)
	assert.Equal(t, val2.OwnerIP, got.OwnerIP)
	assert.Equal(t, val2.OwnerIdx, got.OwnerIdx)

	// IterateWithCallback should find both entries
	count := 0
	steerMap.IterateWithCallback(func(k *EgressSteerKey4, v *EgressSteerVal4) {
		count++
	})
	assert.Equal(t, 2, count)

	// Delete first entry
	err = steerMap.Delete(&key1)
	assert.Nil(t, err)

	// Lookup deleted entry should fail
	_, err = steerMap.Lookup(&key1)
	assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist))

	// Second entry should still exist
	got, err = steerMap.Lookup(&key2)
	assert.Nil(t, err)
	assert.Equal(t, val2.OwnerIP, got.OwnerIP)
	assert.Equal(t, val2.OwnerIdx, got.OwnerIdx)
}
