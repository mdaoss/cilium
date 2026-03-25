// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"egressmaps",
	"Egressmaps provide access to the egress gateway datapath maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createPolicyMapFromDaemonConfig),
	cell.Provide(createSteerMapFromDaemonConfig),
	cell.Provide(createReverseMapFromDaemonConfig),
)

func createReverseMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
}) (out struct {
	cell.Out

	bpf.MapOut[ReverseMap]
}) {
	if !in.EnableIPv4EgressGateway {
		return
	}

	out.MapOut = bpf.NewMapOut(ReverseMap(createReverseMap(in.Lifecycle, ebpf.PinByName)))
	return
}

func createSteerMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
}) (out struct {
	cell.Out

	bpf.MapOut[SteerMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_GW_STEER_MAP_SIZE": fmt.Sprint(SteerMapMaxSize),
	}

	if !in.EnableIPv4EgressGateway {
		return
	}

	out.MapOut = bpf.NewMapOut(SteerMap(createSteerMap(in.Lifecycle, ebpf.PinByName)))
	return
}
