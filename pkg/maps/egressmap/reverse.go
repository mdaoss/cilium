// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	ReverseMapName    = "cilium_egress_gw_reverse4"
	ReverseMapMaxSize = 64
)

// EgressReverseKey4 is the key for the egress gateway reverse lookup map.
// It maps an egress IP to its gateway pair for HA reply-path steering.
type EgressReverseKey4 struct {
	EgressIP types.IPv4 `align:"egress_ip"`
}

func (k *EgressReverseKey4) New() bpf.MapKey { return &EgressReverseKey4{} }

func (k *EgressReverseKey4) String() string {
	return fmt.Sprintf("egress_ip=%s", k.EgressIP)
}

// EgressReverseVal4 is the value for the egress gateway reverse lookup map.
type EgressReverseVal4 struct {
	GatewayIP0 types.IPv4 `align:"gateway_ip_0"`
	GatewayIP1 types.IPv4 `align:"gateway_ip_1"`
}

func (v *EgressReverseVal4) New() bpf.MapValue { return &EgressReverseVal4{} }

func (v *EgressReverseVal4) String() string {
	return fmt.Sprintf("gw0=%s gw1=%s", v.GatewayIP0, v.GatewayIP1)
}

// ReverseMap provides access to the egress gateway reverse lookup BPF map.
type ReverseMap interface {
	Update(egressIP, gatewayIP0, gatewayIP1 netip.Addr) error
	Delete(egressIP netip.Addr) error
	IterateWithCallback(func(*EgressReverseKey4, *EgressReverseVal4)) error
}

type reverseMap struct {
	m *bpf.Map
}

func createReverseMap(lc cell.Lifecycle, pinning ebpf.PinType) *reverseMap {
	m := bpf.NewMap(
		ReverseMapName,
		ebpf.Hash,
		&EgressReverseKey4{},
		&EgressReverseVal4{},
		ReverseMapMaxSize,
		0,
	)

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

	return &reverseMap{m}
}

func (rm *reverseMap) Update(egressIP, gatewayIP0, gatewayIP1 netip.Addr) error {
	key := EgressReverseKey4{}
	key.EgressIP.FromAddr(egressIP)
	val := EgressReverseVal4{}
	val.GatewayIP0.FromAddr(gatewayIP0)
	val.GatewayIP1.FromAddr(gatewayIP1)
	return rm.m.Update(&key, &val)
}

func (rm *reverseMap) Delete(egressIP netip.Addr) error {
	key := EgressReverseKey4{}
	key.EgressIP.FromAddr(egressIP)
	return rm.m.Delete(&key)
}

func (rm *reverseMap) IterateWithCallback(cb func(*EgressReverseKey4, *EgressReverseVal4)) error {
	return rm.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		cb(k.(*EgressReverseKey4), v.(*EgressReverseVal4))
	})
}
