// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"
	"go4.org/netipx"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/netdevice"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// policyGatewayConfig is the internal representation of an egress gateway,
// describing which node should act as egress gateway for a given policy.
type policyGatewayConfig struct {
	nodeSelector api.EndpointSelector
	iface        string
	egressIP     netip.Addr
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string
	// egressIP is the IP used to SNAT traffic
	egressIP netip.Addr
	// gatewayIP is the node internal IP of gateway slot 0 (fixed assignment)
	gatewayIP netip.Addr
	// gatewayIP1 is the node internal IP of gateway slot 1 (fixed assignment)
	gatewayIP1 netip.Addr
	// activeGW is a bitmask indicating which gateways are currently active.
	// Uses egressmap.ActiveGW0, ActiveGW1, ActiveGWBoth constants.
	activeGW uint32
	// localNodeConfiguredAsGateway tells if the local node is configured to
	// act as an egress gateway node for this config.
	// This information is used to decide if it is necessary to relax the rp_filter
	// on the interface used to SNAT traffic
	localNodeConfiguredAsGateway bool
}

// PolicyConfig is the internal representation of CiliumEgressGatewayPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix

	policyGwConfig *policyGatewayConfig

	matchedEndpoints map[endpointID]*endpointMetadata
	gatewayConfig    gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *PolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) {
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)

	for _, endpoint := range epDataStore {
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

func (config *policyGatewayConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	gwc := gatewayConfig{
		egressIP:   netip.IPv4Unspecified(),
		gatewayIP:  GatewayNotFoundIPv4,
		gatewayIP1: GatewayNotFoundIPv4,
	}

	policyGwc := config.policyGwConfig

	// Collect up to 2 matching gateway nodes preserving their sorted slot
	// assignment. manager.nodes is sorted by name for determinism.
	// Unlike the old approach that skipped unhealthy/held nodes entirely,
	// we always assign IPs to fixed slots and track health separately via
	// the activeGW bitmask. This ensures each gateway keeps its fixed
	// SNAT port range even when the other gateway is down.
	type gwSlot struct {
		addr   netip.Addr
		node   nodeTypes.Node
		active bool
	}
	var slots []gwSlot

	for _, node := range manager.nodes {
		if !policyGwc.selectsNodeAsGateway(node) {
			continue
		}

		addr, ok := netipx.FromStdIP(node.GetK8sNodeIP())
		if !ok {
			continue
		}

		// Determine whether this node is currently active.
		active := true
		if _, unhealthy := manager.unhealthyGateways[node.Name]; unhealthy {
			active = false
		}
		if holdUntil, held := manager.recoveredGatewayHoldUntil[node.Name]; held {
			if time.Now().Before(holdUntil) {
				active = false
			} else {
				delete(manager.recoveredGatewayHoldUntil, node.Name)
				if timer := manager.recoveredGatewayTimers[node.Name]; timer != nil {
					timer.Stop()
					delete(manager.recoveredGatewayTimers, node.Name)
				}
			}
		}

		slots = append(slots, gwSlot{addr: addr, node: node, active: active})
		if len(slots) >= 2 {
			break
		}
	}

	// Assign IPs to fixed slots and build the activeGW bitmask.
	for i, slot := range slots {
		switch i {
		case 0:
			gwc.gatewayIP = slot.addr
			if slot.active {
				gwc.activeGW |= egressmap.ActiveGW0
			}
		case 1:
			gwc.gatewayIP1 = slot.addr
			if slot.active {
				gwc.activeGW |= egressmap.ActiveGW1
			}
		}

		// Always derive local config so the gateway knows its egress
		// IP/interface, even if currently marked inactive.
		if slot.node.IsLocal() {
			err := gwc.deriveFromPolicyGatewayConfig(policyGwc)
			if err != nil {
				logger := log.WithFields(logrus.Fields{
					logfields.CiliumEgressGatewayPolicyName: config.id,
					logfields.Interface:                     policyGwc.iface,
					logfields.EgressIP:                      policyGwc.egressIP,
				})
				logger.WithError(err).Error("Failed to derive policy gateway configuration")
			}
		}
	}

	config.gatewayConfig = gwc
}

// deriveFromPolicyGatewayConfig retrieves all the missing gateway configuration
// data (such as egress IP or interface) given a policy egress gateway config
func (gwc *gatewayConfig) deriveFromPolicyGatewayConfig(gc *policyGatewayConfig) error {
	var err error

	gwc.localNodeConfiguredAsGateway = false

	switch {
	case gc.iface != "":
		// If the gateway config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP
		gwc.ifaceName = gc.iface
		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP.IsValid():
		// Use the egress IP from the policy spec for SNAT, even if it is a virtual IP
		// (e.g. announced via BGP/MetalLB) not assigned to any local interface.
		// When the IP is not local, fall back to the default-route interface for egress.
		gwc.egressIP = gc.egressIP
		gwc.ifaceName, err = netdevice.GetIfaceWithIPv4Address(gc.egressIP)
		if err != nil {
			iface, err2 := route.NodeDeviceWithDefaultRoute(true, false)
			if err2 != nil {
				return fmt.Errorf("egress IP %s not local and no default route interface: %w", gc.egressIP, err2)
			}
			gwc.ifaceName = iface.Attrs().Name
		}
	default:
		// If the gateway config doesn't specify any egress IP or interface, use the
		// interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	gwc.localNodeConfiguredAsGateway = true

	return nil
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(netip.Addr, netip.Prefix, bool, *gatewayConfig)) {

	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			isExcludedCIDR := false
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, isExcludedCIDR, &config.gatewayConfig)
			}

			isExcludedCIDR = true
			for _, excludedCIDR := range config.excludedCIDRs {
				f(endpointIP, excludedCIDR, isExcludedCIDR, &config.gatewayConfig)
			}
		}
	}
}

// ParseCEGP takes a CiliumEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseCEGP(cegp *v2.CiliumEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var excludedCIDRs []netip.Prefix

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	destinationCIDRs := cegp.Spec.DestinationCIDRs
	if destinationCIDRs == nil {
		return nil, fmt.Errorf("destinationCIDRs can't be empty")
	}

	egressGateway := cegp.Spec.EgressGateway
	if egressGateway == nil {
		return nil, fmt.Errorf("egressGateway can't be empty")
	}

	if egressGateway.Interface != "" && egressGateway.EgressIP != "" {
		return nil, fmt.Errorf("gateway configuration can't specify both an interface and an egress IP")
	}

	policyGwc := &policyGatewayConfig{
		nodeSelector: api.NewESFromK8sLabelSelector("", egressGateway.NodeSelector),
		iface:        egressGateway.Interface,
	}
	// EgressIP is not a required field, validate and parse it only if non-empty
	if egressGateway.EgressIP != "" {
		addr, err := netip.ParseAddr(egressGateway.EgressIP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse egress IP %s: %w", egressGateway.EgressIP, err)
		}
		policyGwc.egressIP = addr
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %w", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range cegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse excluded CIDR %s: %w", cidr, err)
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, egressRule := range cegp.Spec.Selectors {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", prefixedNsSelector, egressRule.PodSelector))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
		} else {
			return nil, fmt.Errorf("cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		excludedCIDRs:     excludedCIDRs,
		matchedEndpoints:  make(map[endpointID]*endpointMetadata),
		policyGwConfig:    policyGwc,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCEGPConfigID takes a CiliumEgressGatewayPolicy CR and returns only the config id
func ParseCEGPConfigID(cegp *v2.CiliumEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: cegp.Name,
	}
}
