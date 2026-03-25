// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFEgressSteerCmd represents the bpf egress steer command
var BPFEgressSteerCmd = &cobra.Command{
	Use:   "steer",
	Short: "Manage the egress gateway HA steering map",
}

func init() {
	BPFEgressCmd.AddCommand(BPFEgressSteerCmd)
}
