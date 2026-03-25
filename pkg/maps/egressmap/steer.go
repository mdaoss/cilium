// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	SteerMapName    = "cilium_egress_gw_steer4"
	SteerMapMaxSize = 65536
)

// EgressSteerKey4 is the key for the egress gateway HA steering map.
// It represents the reply-path 5-tuple before reverse SNAT.
type EgressSteerKey4 struct {
	SAddr   types.IPv4 `align:"saddr"`
	DAddr   types.IPv4 `align:"daddr"`
	SPort   uint16     `align:"sport"`
	DPort   uint16     `align:"dport"`
	NextHdr uint8      `align:"nexthdr"`
	Pad     [3]uint8   `align:"pad"`
}

func (k *EgressSteerKey4) New() bpf.MapKey { return &EgressSteerKey4{} }

func (k *EgressSteerKey4) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d proto=%d",
		k.SAddr, k.SPort, k.DAddr, k.DPort, k.NextHdr)
}

// EgressSteerVal4 is the value for the egress gateway HA steering map.
// It identifies which gateway node owns the flow.
type EgressSteerVal4 struct {
	OwnerIP  types.IPv4 `align:"owner_ip"`
	OwnerIdx uint8      `align:"owner_idx"`
	Pad      [3]uint8   `align:"pad"`
}

func (v *EgressSteerVal4) New() bpf.MapValue { return &EgressSteerVal4{} }

func (v *EgressSteerVal4) String() string {
	return fmt.Sprintf("owner=%s idx=%d", v.OwnerIP, v.OwnerIdx)
}

// SteerMap provides access to the egress gateway HA steering BPF map.
type SteerMap interface {
	Lookup(key *EgressSteerKey4) (*EgressSteerVal4, error)
	Update(key *EgressSteerKey4, val *EgressSteerVal4) error
	Delete(key *EgressSteerKey4) error
	IterateWithCallback(func(*EgressSteerKey4, *EgressSteerVal4)) error
	Flush() int
}

type steerMap struct {
	m *bpf.Map
}

func createSteerMap(lc cell.Lifecycle, pinning ebpf.PinType) *steerMap {
	m := bpf.NewMap(
		SteerMapName,
		ebpf.LRUHash,
		&EgressSteerKey4{},
		&EgressSteerVal4{},
		SteerMapMaxSize,
		0,
	).WithPressureMetric()

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &steerMap{m}
}

// CreatePrivateSteerMap creates an unpinned steering map for testing.
func CreatePrivateSteerMap(lc cell.Lifecycle) SteerMap {
	return createSteerMap(lc, ebpf.PinNone)
}

// OpenPinnedSteerMap opens the pinned steering map for CLI access.
func OpenPinnedSteerMap() (SteerMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(SteerMapName), &EgressSteerKey4{}, &EgressSteerVal4{})
	if err != nil {
		return nil, err
	}

	return &steerMap{m}, nil
}

func (sm *steerMap) Lookup(key *EgressSteerKey4) (*EgressSteerVal4, error) {
	val, err := sm.m.Lookup(key)
	if err != nil {
		return nil, err
	}
	return val.(*EgressSteerVal4), nil
}

func (sm *steerMap) Update(key *EgressSteerKey4, val *EgressSteerVal4) error {
	return sm.m.Update(key, val)
}

func (sm *steerMap) Delete(key *EgressSteerKey4) error {
	return sm.m.Delete(key)
}

func (sm *steerMap) IterateWithCallback(cb func(*EgressSteerKey4, *EgressSteerVal4)) error {
	return sm.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		cb(k.(*EgressSteerKey4), v.(*EgressSteerVal4))
	})
}

func (sm *steerMap) Flush() int {
	count := 0
	var keysToDelete []*EgressSteerKey4
	sm.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := *k.(*EgressSteerKey4)
		keysToDelete = append(keysToDelete, &key)
	})
	for _, key := range keysToDelete {
		if err := sm.m.Delete(key); err == nil {
			count++
		}
	}
	return count
}
