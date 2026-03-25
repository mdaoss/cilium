// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName = "cilium_egress_gw_policy_v4"
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyKey4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm_key"`

	SourceIP types.IPv4 `align:"saddr"`
	DestCIDR types.IPv4 `align:"daddr"`
}

// HA active-gateway bitmask constants for EgressPolicyVal4.ActiveGW.
const (
	ActiveGW0    uint32 = 1 // gateway_ip_0 is active
	ActiveGW1    uint32 = 2 // gateway_ip_1 is active
	ActiveGWBoth uint32 = 3 // both gateways active
)

// EgressPolicyVal4 is the value of an egress policy map.
// It carries two gateways in fixed slots for active/active HA egress.
// The ActiveGW bitmask indicates which gateways are currently reachable.
type EgressPolicyVal4 struct {
	EgressIP   types.IPv4 `align:"egress_ip"`
	GatewayIP0 types.IPv4 `align:"gateway_ip_0"`
	GatewayIP1 types.IPv4 `align:"gateway_ip_1"`
	ActiveGW   uint32     `align:"active_gw"`
}

type PolicyConfig struct {
	// EgressGatewayPolicyMapMax is the maximum number of entries
	// allowed in the BPF egress gateway policy map.
	EgressGatewayPolicyMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	EgressGatewayPolicyMapMax: 1 << 14,
}

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("egress-gateway-policy-map-max", def.EgressGatewayPolicyMapMax, "Maximum number of entries in egress gateway policy map")
}

// PolicyMap is used to communicate EGW policies to the datapath.
type PolicyMap interface {
	Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error)
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP0, gatewayIP1 netip.Addr, activeGW uint32) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
	IterateWithCallback(EgressPolicyIterateCallback) error
}

// policyMap is the internal representation of an egress policy map.
type policyMap struct {
	m *bpf.Map
}

func createPolicyMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
	PolicyConfig
}) (out struct {
	cell.Out

	bpf.MapOut[PolicyMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_POLICY_MAP":      PolicyMapName,
		"EGRESS_POLICY_MAP_SIZE": fmt.Sprint(in.EgressGatewayPolicyMapMax),
	}

	if !in.EnableIPv4EgressGateway {
		return
	}

	out.MapOut = bpf.NewMapOut(PolicyMap(createPolicyMap(in.Lifecycle, in.PolicyConfig, ebpf.PinByName)))
	return
}

// CreatePrivatePolicyMap creates an unpinned policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap(lc cell.Lifecycle, cfg PolicyConfig) PolicyMap {
	return createPolicyMap(lc, cfg, ebpf.PinNone)
}

func createPolicyMap(lc cell.Lifecycle, cfg PolicyConfig, pinning ebpf.PinType) *policyMap {
	m := bpf.NewMap(
		PolicyMapName,
		ebpf.LPMTrie,
		&EgressPolicyKey4{},
		&EgressPolicyVal4{},
		cfg.EgressGatewayPolicyMapMax,
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
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &policyMap{m}
}

func OpenPinnedPolicyMap() (PolicyMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(PolicyMapName), &EgressPolicyKey4{}, &EgressPolicyVal4{})
	if err != nil {
		return nil, err
	}

	return &policyMap{m}, nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey4(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey4 {
	key := EgressPolicyKey4{}

	ones := destPrefix.Bits()
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits + uint32(ones)

	return key
}

// NewEgressPolicyVal4 returns a new EgressPolicyVal4 for the given egress IP,
// two gateway IPs in fixed slots, and the active-gateway bitmask.
func NewEgressPolicyVal4(egressIP, gatewayIP0, gatewayIP1 netip.Addr, activeGW uint32) EgressPolicyVal4 {
	val := EgressPolicyVal4{}

	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP0.FromAddr(gatewayIP0)
	val.GatewayIP1.FromAddr(gatewayIP1)
	val.ActiveGW = activeGW

	return val
}

// String returns the string representation of an egress policy key.
func (k *EgressPolicyKey4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-PolicyStaticPrefixBits)
}

// New returns an egress policy key
func (k *EgressPolicyKey4) New() bpf.MapKey { return &EgressPolicyKey4{} }

// Match returns true if the sourceIP and destCIDR parameters match the egress
// policy key.
func (k *EgressPolicyKey4) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP &&
		k.GetDestCIDR() == destCIDR
}

// GetSourceIP returns the egress policy key's source IP.
func (k *EgressPolicyKey4) GetSourceIP() netip.Addr {
	addr, _ := netipx.FromStdIP(k.SourceIP.IP())
	return addr
}

// GetDestCIDR returns the egress policy key's destination CIDR.
func (k *EgressPolicyKey4) GetDestCIDR() netip.Prefix {
	addr, _ := netipx.FromStdIP(k.DestCIDR.IP())
	return netip.PrefixFrom(addr, int(k.PrefixLen-PolicyStaticPrefixBits))
}

// New returns an egress policy value
func (v *EgressPolicyVal4) New() bpf.MapValue { return &EgressPolicyVal4{} }

// Match returns true if the egressIP, both gatewayIPs, and activeGW flags
// match the egress policy value.
func (v *EgressPolicyVal4) Match(egressIP, gatewayIP0, gatewayIP1 netip.Addr, activeGW uint32) bool {
	return v.GetEgressAddr() == egressIP &&
		v.GetGatewayAddr0() == gatewayIP0 &&
		v.GetGatewayAddr1() == gatewayIP1 &&
		v.ActiveGW == activeGW
}

// GetEgressAddr returns the egress policy value's egress IP.
func (v *EgressPolicyVal4) GetEgressAddr() netip.Addr {
	return v.EgressIP.Addr()
}

// GetGatewayAddr0 returns the egress policy value's first gateway IP.
func (v *EgressPolicyVal4) GetGatewayAddr0() netip.Addr {
	return v.GatewayIP0.Addr()
}

// GetGatewayAddr1 returns the egress policy value's second gateway IP.
func (v *EgressPolicyVal4) GetGatewayAddr1() netip.Addr {
	return v.GatewayIP1.Addr()
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyVal4) String() string {
	return fmt.Sprintf("gw0=%s gw1=%s egress=%s active=%d", v.GetGatewayAddr0(), v.GetGatewayAddr1(), v.GetEgressAddr(), v.ActiveGW)
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *policyMap) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val, err := m.m.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*EgressPolicyVal4), err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs and active-gateway bitmask.
func (m *policyMap) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP0, gatewayIP1 netip.Addr, activeGW uint32) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := NewEgressPolicyVal4(egressIP, gatewayIP0, gatewayIP1, activeGW)

	return m.m.Update(&key, &val)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *policyMap) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)

	return m.m.Delete(&key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m policyMap) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EgressPolicyKey4)
		value := v.(*EgressPolicyVal4)

		cb(key, value)
	})
}
