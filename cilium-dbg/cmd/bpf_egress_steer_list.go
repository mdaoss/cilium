// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	egressSteerListUsage = "List egress gateway HA steering map entries."
)

type egressSteerEntry struct {
	SAddr    string
	DAddr    string
	SPort    uint16
	DPort    uint16
	Protocol uint8
	OwnerIP  string
	OwnerIdx uint8
}

var bpfEgressSteerListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress gateway HA steering map entries",
	Long:    egressSteerListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress steer list")

		steerMap, err := egressmap.OpenPinnedSteerMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find egress gateway steering bpf map")
				return
			}

			Fatalf("Cannot open egress gateway steering bpf map: %s", err)
		}

		entries := []egressSteerEntry{}
		parse := func(key *egressmap.EgressSteerKey4, val *egressmap.EgressSteerVal4) {
			entries = append(entries, egressSteerEntry{
				SAddr:    key.SAddr.String(),
				DAddr:    key.DAddr.String(),
				SPort:    key.SPort,
				DPort:    key.DPort,
				Protocol: key.NextHdr,
				OwnerIP:  val.OwnerIP.String(),
				OwnerIdx: val.OwnerIdx,
			})
		}

		if err := steerMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress steering map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
			}
			return
		}

		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printEgressSteerList(entries)
		}
	},
}

func printEgressSteerList(entries []egressSteerEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source\tDestination\tSPort\tDPort\tProto\tOwner IP\tIdx")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%d\n",
			e.SAddr, e.DAddr, e.SPort, e.DPort, e.Protocol, e.OwnerIP, e.OwnerIdx)
	}

	w.Flush()
}

func init() {
	BPFEgressSteerCmd.AddCommand(bpfEgressSteerListCmd)
	command.AddOutputOption(bpfEgressSteerListCmd)
}
