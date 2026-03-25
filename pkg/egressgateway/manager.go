// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"go4.org/netipx"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "egressgateway")
	// GatewayNotFoundIPv4 is a special IP value used as gatewayIP in the BPF policy
	// map to indicate no gateway was found for the given policy
	GatewayNotFoundIPv4 = netip.IPv4Unspecified()
	// ExcludedCIDRIPv4 is a special IP value used as gatewayIP in the BPF policy map
	// to indicate the entry is for an excluded CIDR and should skip egress gateway
	ExcludedCIDRIPv4 = netip.MustParseAddr("0.0.0.1")
	// EgressIPNotFoundIPv4 is a special IP value used as egressIP in the BPF policy map
	// to indicate no egressIP was found for the given policy
	EgressIPNotFoundIPv4 = netip.IPv4Unspecified()
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgateway",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
	cell.Provide(newPolicyResource),
)

type eventType int

const (
	eventNone = eventType(1 << iota)
	eventK8sSyncDone
	eventAddPolicy
	eventDeletePolicy
	eventUpdateEndpoint
	eventDeleteEndpoint
)

type Config struct {
	// Default amount of time between triggers of egress gateway state
	// reconciliations are invoked
	EgressGatewayReconciliationTriggerInterval time.Duration

	// EgressGatewayProbeInterval is the interval between health probes
	// to remote gateway nodes. The prober TCP-connects to the Cilium
	// health port (4240) on each gateway. After consecutive failures
	// (failure-threshold × this interval), the gateway is removed from
	// the policy map. Set to 0 to disable gateway health probing.
	EgressGatewayProbeInterval time.Duration

	// EgressGatewayProbeTimeout is the TCP connect timeout for each
	// health probe to a remote gateway node.
	EgressGatewayProbeTimeout time.Duration

	// EgressGatewayProbeRecoveryThreshold is how many consecutive successful
	// probes are required before a previously-failed gateway is restored to
	// the policy map. A higher value gives the recovered Cilium agent more
	// time to finish loading BPF programs and populating maps.
	EgressGatewayProbeRecoveryThreshold int

	// EgressGatewayProbeRecoveryHoldTime keeps a recovered gateway in
	// single-gateway mode for an additional grace period before it can be
	// selected again. This gives external reply-path convergence (ECMP/BGP)
	// time to settle and reduces post-recovery asymmetric-reply pressure.
	// Set to 0 to disable the hold.
	EgressGatewayProbeRecoveryHoldTime time.Duration
}

var defaultConfig = Config{
	EgressGatewayReconciliationTriggerInterval: 1 * time.Second,
	EgressGatewayProbeInterval:                 1 * time.Second,
	EgressGatewayProbeTimeout:                  defaultProbeTimeout,
	EgressGatewayProbeRecoveryThreshold:        defaultRecoveryThreshold,
	EgressGatewayProbeRecoveryHoldTime:         0,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("egress-gateway-reconciliation-trigger-interval", def.EgressGatewayReconciliationTriggerInterval, "Time between triggers of egress gateway state reconciliations")
	flags.Duration("egress-gateway-probe-interval", def.EgressGatewayProbeInterval, "Interval between health probes to remote egress gateway nodes (0 to disable)")
	flags.Duration("egress-gateway-probe-timeout", def.EgressGatewayProbeTimeout, "TCP connect timeout for each health probe to a remote gateway node")
	flags.Int("egress-gateway-probe-recovery-threshold", def.EgressGatewayProbeRecoveryThreshold, "Consecutive successful probes required before restoring a recovered gateway")
	flags.Duration("egress-gateway-probe-recovery-hold-time", def.EgressGatewayProbeRecoveryHoldTime, "Additional hold time after a gateway recovers before it is re-selected for egress")
}

// The egressgateway manager stores the internal data tracking the node, policy,
// endpoint, and lease mappings. It also hooks up all the callbacks to update
// egress bpf policy map accordingly.
type Manager struct {
	lock.Mutex

	// allCachesSynced is true when all k8s objects we depend on have had
	// their initial state synced.
	allCachesSynced bool

	// nodes stores nodes sorted by their name. The entries are sorted
	// to ensure consistent gateway selection across all agents.
	nodes []nodeTypes.Node

	// policies allows reading policy CRD from k8s.
	policies resource.Resource[*Policy]

	// nodesResource allows reading node CRD from k8s.
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode]

	// endpoints allows reading endpoint CRD from k8s.
	endpoints resource.Resource[*k8sTypes.CiliumEndpoint]

	// policyConfigs stores policy configs indexed by policyID
	policyConfigs map[policyID]*PolicyConfig

	// policyConfigsBySourceIP stores slices of policy configs indexed by
	// the policies' source/endpoint IPs
	policyConfigsBySourceIP map[string][]*PolicyConfig

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// policyMap communicates the active policies to the datapath.
	policyMap egressmap.PolicyMap

	// reverseMap maps egress IPs to their gateway pairs for HA reply steering.
	reverseMap egressmap.ReverseMap

	// steerMap is the HA steering map used to direct reply traffic to the
	// correct gateway. Flushed on gateway recovery to remove stale entries
	// from single-gateway mode.
	steerMap egressmap.SteerMap

	// reconciliationTriggerInterval is the amount of time between triggers
	// of reconciliations are invoked
	reconciliationTriggerInterval time.Duration

	// eventsBitmap is a bitmap that tracks which type of events has been
	// received by the manager (e.g. node added or policy removed) since the
	// last invocation of the reconciliation logic
	eventsBitmap eventType

	// reconciliationTrigger is the trigger used to reconcile the state of
	// the node with the desired egress gateway state.
	// The trigger is used to batch multiple updates together
	reconciliationTrigger *trigger.Trigger

	// reconciliationEventsCount keeps track of how many reconciliation
	// events have occoured
	reconciliationEventsCount atomic.Uint64

	sysctl sysctl.Sysctl

	// gwProber periodically checks gateway node health via TCP connects
	// to the Cilium health port. When a gateway becomes unreachable, it
	// is excluded from policy map entries until it recovers.
	gwProber *gatewayProber

	// gwHealthCh receives health status changes from the gateway prober.
	gwHealthCh chan gatewayHealthEvent

	// unhealthyGateways tracks gateway nodes that failed health probes.
	// Nodes in this set are skipped during gateway selection in
	// regenerateGatewayConfig(). Protected by Manager.Mutex.
	unhealthyGateways map[string]struct{}

	// recoveredGatewayHoldUntil keeps recovered gateways in a temporary hold
	// state after probe-based recovery. While a node is in this map and
	// holdUntil is in the future, gateway selection treats it as unavailable.
	recoveredGatewayHoldUntil map[string]time.Time

	// recoveredGatewayTimers trigger reconciliation when a recovery-hold
	// period elapses.
	recoveredGatewayTimers map[string]*time.Timer

	// probeRecoveryHoldTime is the configured post-recovery hold duration.
	probeRecoveryHoldTime time.Duration
}

type Params struct {
	cell.In

	Config            Config
	DaemonConfig      *option.DaemonConfig
	IdentityAllocator identityCache.IdentityAllocator
	PolicyMap         egressmap.PolicyMap
	ReverseMap        egressmap.ReverseMap
	SteerMap          egressmap.SteerMap
	Policies          resource.Resource[*Policy]
	Nodes             resource.Resource[*cilium_api_v2.CiliumNode]
	Endpoints         resource.Resource[*k8sTypes.CiliumEndpoint]
	Sysctl            sysctl.Sysctl

	Lifecycle cell.Lifecycle
}

func NewEgressGatewayManager(p Params) (out struct {
	cell.Out

	*Manager
	defines.NodeOut
	tunnel.EnablerOut
}, err error) {
	dcfg := p.DaemonConfig

	if !dcfg.EnableIPv4EgressGateway {
		return out, nil
	}

	if dcfg.IdentityAllocationMode == option.IdentityAllocationModeKVstore {
		return out, errors.New("egress gateway is not supported in KV store identity allocation mode")
	}

	if dcfg.EnableHighScaleIPcache {
		return out, errors.New("egress gateway is not supported in high scale IPcache mode")
	}

	if dcfg.EnableCiliumEndpointSlice {
		return out, errors.New("egress gateway is not supported in combination with the CiliumEndpointSlice feature")
	}

	if !dcfg.EnableIPv4Masquerade || !dcfg.EnableBPFMasquerade {
		return out, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	out.Manager, err = newEgressGatewayManager(p)
	if err != nil {
		return out, err
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY": "1",
	}

	if dcfg.EnableEgressGatewayHARedirect {
		out.NodeDefines["ENABLE_EGRESS_GATEWAY_HA_REDIRECT"] = "1"
	}

	out.EnablerOut = tunnel.NewEnabler(true)

	return out, nil
}

func newEgressGatewayManager(p Params) (*Manager, error) {
	healthCh := make(chan gatewayHealthEvent, 16)
	manager := &Manager{
		policyConfigs:                 make(map[policyID]*PolicyConfig),
		policyConfigsBySourceIP:       make(map[string][]*PolicyConfig),
		epDataStore:                   make(map[endpointID]*endpointMetadata),
		identityAllocator:             p.IdentityAllocator,
		reconciliationTriggerInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		policyMap:                     p.PolicyMap,
		reverseMap:                    p.ReverseMap,
		steerMap:                      p.SteerMap,
		policies:                      p.Policies,
		ciliumNodes:                   p.Nodes,
		endpoints:                     p.Endpoints,
		sysctl:                        p.Sysctl,
		gwHealthCh:                    healthCh,
		unhealthyGateways:             make(map[string]struct{}),
		recoveredGatewayHoldUntil:     make(map[string]time.Time),
		recoveredGatewayTimers:        make(map[string]*time.Timer),
		probeRecoveryHoldTime:         p.Config.EgressGatewayProbeRecoveryHoldTime,
	}

	if p.Config.EgressGatewayProbeInterval > 0 {
		manager.gwProber = newGatewayProber(healthCh, p.Config.EgressGatewayProbeInterval, p.Config.EgressGatewayProbeTimeout, p.Config.EgressGatewayProbeRecoveryThreshold)
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "egress_gateway_reconciliation",
		MinInterval: p.Config.EgressGatewayReconciliationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			reason := strings.Join(reasons, ", ")
			log.WithField(logfields.Reason, reason).Debug("reconciliation triggered")

			manager.Lock()
			defer manager.Unlock()

			manager.reconcileLocked()
		},
	})
	if err != nil {
		return nil, err
	}

	manager.reconciliationTrigger = t

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				manager.processEvents(ctx)
			}()
			if manager.gwProber != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					manager.gwProber.run(ctx)
				}()
			}

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			wg.Wait()
			return nil
		},
	})

	return manager, nil
}

func (manager *Manager) setEventBitmap(events ...eventType) {
	for _, e := range events {
		manager.eventsBitmap |= e
	}
}

func (manager *Manager) eventBitmapIsSet(events ...eventType) bool {
	for _, e := range events {
		if manager.eventsBitmap&e != 0 {
			return true
		}
	}

	return false
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %w", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// processEvents spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) processEvents(ctx context.Context) {
	var policySync, nodeSync, endpointSync bool
	maybeTriggerReconcile := func() {
		if !policySync || !nodeSync || !endpointSync {
			return
		}

		manager.Lock()
		defer manager.Unlock()

		if manager.allCachesSynced {
			return
		}

		manager.allCachesSynced = true
		manager.setEventBitmap(eventK8sSyncDone)
		manager.reconciliationTrigger.TriggerWithReason("k8s sync done")
	}

	// here we try to mimic the same exponential backoff retry logic used by
	// the identity allocator, where the minimum retry timeout is set to 20
	// milliseconds and the max number of attempts is 16 (so 20ms * 2^16 ==
	// ~20 minutes)
	endpointsRateLimit := workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond*20, time.Minute*20)

	policyEvents := manager.policies.Events(ctx)
	nodeEvents := manager.ciliumNodes.Events(ctx)
	endpointEvents := manager.endpoints.Events(ctx, resource.WithRateLimiter(endpointsRateLimit))

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-policyEvents:
			if event.Kind == resource.Sync {
				policySync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handlePolicyEvent(event)
			}

		case event := <-nodeEvents:
			if event.Kind == resource.Sync {
				nodeSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleNodeEvent(event)
			}

		case event := <-endpointEvents:
			if event.Kind == resource.Sync {
				endpointSync = true
				maybeTriggerReconcile()
				event.Done(nil)
			} else {
				manager.handleEndpointEvent(event)
			}

		case event := <-manager.gwHealthCh:
			manager.handleGatewayHealthEvent(event)
		}
	}
}

func (manager *Manager) handlePolicyEvent(event resource.Event[*Policy]) {
	switch event.Kind {
	case resource.Upsert:
		err := manager.onAddEgressPolicy(event.Object)
		event.Done(err)
	case resource.Delete:
		manager.onDeleteEgressPolicy(event.Object)
		event.Done(nil)
	}
}

// Event handlers

// onAddEgressPolicy parses the given policy config, and updates internal state
// with the config fields.
func (manager *Manager) onAddEgressPolicy(policy *Policy) error {
	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, policy.Name)

	config, err := ParseCEGP(policy)
	if err != nil {
		logger.WithError(err).Warn("Failed to parse CiliumEgressGatewayPolicy")
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.policyConfigs[config.id]; !ok {
		logger.Debug("Added CiliumEgressGatewayPolicy")
	} else {
		logger.Debug("Updated CiliumEgressGatewayPolicy")
	}

	config.updateMatchedEndpointIDs(manager.epDataStore)

	manager.policyConfigs[config.id] = config

	manager.setEventBitmap(eventAddPolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy added")
	return nil
}

// onDeleteEgressPolicy deletes the internal state associated with the given
// policy, including egress eBPF map entries.
func (manager *Manager) onDeleteEgressPolicy(policy *Policy) {
	configID := ParseCEGPConfigID(policy)

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumEgressGatewayPolicyName, configID.Name)

	if manager.policyConfigs[configID] == nil {
		logger.Warn("Can't delete CiliumEgressGatewayPolicy: policy not found")
	}

	logger.Debug("Deleted CiliumEgressGatewayPolicy")

	delete(manager.policyConfigs, configID)

	manager.setEventBitmap(eventDeletePolicy)
	manager.reconciliationTrigger.TriggerWithReason("policy deleted")
}

func (manager *Manager) addEndpoint(endpoint *k8sTypes.CiliumEndpoint) error {
	var epData *endpointMetadata
	var err error
	var identityLabels labels.Labels

	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	if endpoint.Identity == nil {
		logger.Warning("Endpoint is missing identity metadata, skipping update to egress policy.")
		return nil
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Warning("Failed to get identity labels for endpoint")
		return err
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update to egress policy.")
		return nil
	}

	if _, ok := manager.epDataStore[epData.id]; ok {
		logger.Debug("Updated CiliumEndpoint")
	} else {
		logger.Debug("Added CiliumEndpoint")
	}

	manager.epDataStore[epData.id] = epData

	manager.setEventBitmap(eventUpdateEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint updated")

	return nil
}

func (manager *Manager) deleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
		logfields.K8sUID:          endpoint.UID,
	})

	logger.Debug("Deleted CiliumEndpoint")
	delete(manager.epDataStore, endpoint.UID)

	manager.setEventBitmap(eventDeleteEndpoint)
	manager.reconciliationTrigger.TriggerWithReason("endpoint deleted")
}

func (manager *Manager) handleEndpointEvent(event resource.Event[*k8sTypes.CiliumEndpoint]) {
	endpoint := event.Object

	if event.Kind == resource.Upsert {
		event.Done(manager.addEndpoint(endpoint))
	} else {
		manager.deleteEndpoint(endpoint)
		event.Done(nil)
	}
}

// handleNodeEvent takes care of node upserts and removals.
func (manager *Manager) handleNodeEvent(event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	node := nodeTypes.ParseCiliumNode(event.Object)

	manager.Lock()
	defer manager.Unlock()

	// Find the node if we already have it.
	nidx, found := slices.BinarySearchFunc(manager.nodes, node, func(a nodeTypes.Node, b nodeTypes.Node) int {
		return cmp.Compare(a.Name, b.Name)
	})

	if event.Kind == resource.Delete {
		// Delete the node if we're aware of it.
		if found {
			manager.nodes = slices.Delete(manager.nodes, nidx, nidx+1)
		}

		manager.reconciliationTrigger.TriggerWithReason("node deleted")
		return
	}

	// Update the node if we have it, otherwise insert in the correct
	// position.
	if found {
		manager.nodes[nidx] = node
	} else {
		manager.nodes = slices.Insert(manager.nodes, nidx, node)
	}

	manager.reconciliationTrigger.TriggerWithReason("node updated")
}

// handleGatewayHealthEvent processes a health status change from the gateway
// prober. When a gateway becomes unhealthy, it is added to the unhealthy set
// so regenerateGatewayConfig() skips it. When it recovers, it is removed
// and the steering map is flushed to clear stale entries from single-gateway
// mode that would cause reply misrouting.
func (manager *Manager) handleGatewayHealthEvent(event gatewayHealthEvent) {
	manager.Lock()
	defer manager.Unlock()

	if event.healthy {
		_, wasUnhealthy := manager.unhealthyGateways[event.nodeName]
		delete(manager.unhealthyGateways, event.nodeName)

		if wasUnhealthy && manager.probeRecoveryHoldTime > 0 {
			holdUntil := time.Now().Add(manager.probeRecoveryHoldTime)
			manager.recoveredGatewayHoldUntil[event.nodeName] = holdUntil

			if existing := manager.recoveredGatewayTimers[event.nodeName]; existing != nil {
				existing.Stop()
			}

			nodeName := event.nodeName
			manager.recoveredGatewayTimers[event.nodeName] = time.AfterFunc(manager.probeRecoveryHoldTime, func() {
				manager.reconciliationTrigger.TriggerWithReason("gateway recovery hold elapsed: " + nodeName)
			})

			log.WithField(logfields.NodeName, event.nodeName).
				WithField("holdDuration", manager.probeRecoveryHoldTime).
				WithField("holdUntil", holdUntil).
				Info("Gateway recovered, entering post-recovery hold before policy restore")
		}

		// When a gateway recovers, flush the steering map.
		// During single-gateway mode the surviving gateway used the full
		// SNAT port range and created steering entries claiming ownership
		// of all flows. After recovery, the port range is partitioned and
		// these stale entries would misdirect replies. Flushing is safe —
		// the steering map is an LRU cache and new entries are created on
		// every SNAT'd packet.
		if wasUnhealthy && manager.steerMap != nil {
			flushed := manager.steerMap.Flush()
			log.WithField("nodeName", event.nodeName).
				WithField("flushedEntries", flushed).
				Info("Gateway recovered, flushed steering map to clear stale entries")
		}
	} else {
		manager.unhealthyGateways[event.nodeName] = struct{}{}
		delete(manager.recoveredGatewayHoldUntil, event.nodeName)
		if timer := manager.recoveredGatewayTimers[event.nodeName]; timer != nil {
			timer.Stop()
			delete(manager.recoveredGatewayTimers, event.nodeName)
		}
	}

	manager.reconciliationTrigger.TriggerWithReason("gateway health changed: " + event.nodeName)
}

// updateProberTargets collects all remote gateway node IPs from the current
// policy configs and updates the prober's target list. Called after
// reconciliation so the prober only probes nodes that are actually gateways.
func (manager *Manager) updateProberTargets() {
	if manager.gwProber == nil {
		return
	}

	seen := make(map[string]struct{})
	var targets []gatewayTarget

	for _, node := range manager.nodes {
		if node.IsLocal() {
			continue
		}

		// Check if this node is selected as gateway by any policy.
		isGateway := false
		for _, pc := range manager.policyConfigs {
			if pc.policyGwConfig.selectsNodeAsGateway(node) {
				isGateway = true
				break
			}
		}
		if !isGateway {
			continue
		}

		if _, ok := seen[node.Name]; ok {
			continue
		}
		seen[node.Name] = struct{}{}

		ip := node.GetK8sNodeIP()
		if ip == nil {
			continue
		}
		addr, ok := netipx.FromStdIP(ip)
		if !ok {
			continue
		}

		targets = append(targets, gatewayTarget{
			name: node.Name,
			ip:   addr,
		})
	}

	manager.gwProber.setTargets(targets)

	// Prune unhealthyGateways entries for nodes that are no longer active
	// probe targets. Use the actual targets slice (not the seen set) because
	// seen includes nodes that matched the gateway selector but failed IP
	// validation — those nodes are not probed, so their stale unhealthy
	// entries must still be pruned.
	activeTargets := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		activeTargets[t.name] = struct{}{}
	}
	needsReconcile := false
	for name := range manager.unhealthyGateways {
		if _, active := activeTargets[name]; !active {
			delete(manager.unhealthyGateways, name)
			delete(manager.recoveredGatewayHoldUntil, name)
			if timer := manager.recoveredGatewayTimers[name]; timer != nil {
				timer.Stop()
				delete(manager.recoveredGatewayTimers, name)
			}
			needsReconcile = true
			log.WithField(logfields.NodeName, name).
				Info("Pruned stale unhealthy gateway entry (node no longer an active target)")
		}
	}
	if needsReconcile {
		if manager.steerMap != nil {
			flushed := manager.steerMap.Flush()
			log.WithField("flushedEntries", flushed).
				Info("Flushed steering map after pruning stale unhealthy gateway entries")
		}
		// Trigger another reconciliation so regenerateGatewayConfig()
		// picks up the now-cleared unhealthy entries.
		manager.reconciliationTrigger.TriggerWithReason("pruned stale unhealthy gateways")
	}
}

func (manager *Manager) updatePoliciesMatchedEndpointIDs() {
	for _, policy := range manager.policyConfigs {
		policy.updateMatchedEndpointIDs(manager.epDataStore)
	}
}

func (manager *Manager) updatePoliciesBySourceIP() {
	manager.policyConfigsBySourceIP = make(map[string][]*PolicyConfig)

	for _, policy := range manager.policyConfigs {
		for _, ep := range policy.matchedEndpoints {
			for _, epIP := range ep.ips {
				ip := epIP.String()
				manager.policyConfigsBySourceIP[ip] = append(manager.policyConfigsBySourceIP[ip], policy)
			}
		}
	}
}

// policyMatches returns true if there exists at least one policy matching the
// given parameters.
//
// This method takes:
//   - a source IP: this is an optimization that allows to iterate only through
//     policies that reference an endpoint with the given source IP
//   - a callback function f: this function is invoked for each policy and for
//     each combination of the policy's endpoints and destination/excludedCIDRs.
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - a boolean value indicating if the CIDR belongs to the excluded ones
// - the gatewayConfig of the  policy
//
// This method returns true whenever the f callback matches one of the endpoint
// and CIDR tuples (i.e. whenever one callback invocation returns true)
func (manager *Manager) policyMatches(sourceIP netip.Addr, f func(netip.Addr, netip.Prefix, bool, *gatewayConfig) bool) bool {
	for _, policy := range manager.policyConfigsBySourceIP[sourceIP.String()] {
		for _, ep := range policy.matchedEndpoints {
			for _, endpointIP := range ep.ips {
				if endpointIP != sourceIP {
					continue
				}

				isExcludedCIDR := false
				for _, dstCIDR := range policy.dstCIDRs {
					if f(endpointIP, dstCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}

				isExcludedCIDR = true
				for _, excludedCIDR := range policy.excludedCIDRs {
					if f(endpointIP, excludedCIDR, isExcludedCIDR, &policy.gatewayConfig) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (manager *Manager) regenerateGatewayConfigs() {
	for _, policyConfig := range manager.policyConfigs {
		policyConfig.regenerateGatewayConfig(manager)
	}
}

func (manager *Manager) relaxRPFilter() error {
	var sysSettings []tables.Sysctl
	ifSet := make(map[string]struct{})

	for _, pc := range manager.policyConfigs {
		if !pc.gatewayConfig.localNodeConfiguredAsGateway {
			continue
		}

		ifaceName := pc.gatewayConfig.ifaceName
		if _, ok := ifSet[ifaceName]; !ok {
			ifSet[ifaceName] = struct{}{}
			sysSettings = append(sysSettings, tables.Sysctl{
				Name:      []string{"net", "ipv4", "conf", ifaceName, "rp_filter"},
				Val:       "2",
				IgnoreErr: false,
			})
		}
	}

	if len(sysSettings) == 0 {
		return nil
	}

	return manager.sysctl.ApplySettings(sysSettings)
}

func (manager *Manager) addMissingEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	addEgressRule := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) {
		policyKey := egressmap.NewEgressPolicyKey4(endpointIP, dstCIDR)
		policyVal, policyPresent := egressPolicies[policyKey]

		gw0 := gwc.gatewayIP
		gw1 := gwc.gatewayIP1
		activeGW := gwc.activeGW
		if excludedCIDR {
			gw0 = ExcludedCIDRIPv4
			gw1 = netip.IPv4Unspecified()
			activeGW = 0
		} else if activeGW == 0 {
			// All configured gateways are currently inactive
			// (unhealthy or in recovery hold). Write NO_GATEWAY
			// to trigger the BPF-level drop. We avoid writing
			// active_gw=0 with valid gateway IPs because that
			// is indistinguishable from legacy entries (where
			// the old pad field was zero) and would fall through
			// to the legacy code path instead of dropping.
			gw0 = GatewayNotFoundIPv4
			gw1 = netip.IPv4Unspecified()
		}

		if policyPresent && policyVal.Match(gwc.egressIP, gw0, gw1, activeGW) {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        endpointIP,
			logfields.DestinationCIDR: dstCIDR.String(),
			logfields.EgressIP:        gwc.egressIP,
			logfields.GatewayIP:       fmt.Sprintf("%s,%s", gw0, gw1),
		})

		if err := manager.policyMap.Update(endpointIP, dstCIDR, gwc.egressIP, gw0, gw1, activeGW); err != nil {
			logger.WithError(err).Error("Error applying egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy applied")
		}
	}

	for _, policyConfig := range manager.policyConfigs {
		policyConfig.forEachEndpointAndCIDR(addEgressRule)
	}
}

// removeUnusedEgressRules is responsible for removing any entry in the egress policy BPF map which
// is not baked by an actual k8s CiliumEgressGatewayPolicy.
func (manager *Manager) removeUnusedEgressRules() {
	egressPolicies := map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4{}
	manager.policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			egressPolicies[*key] = *val
		})

	for policyKey, policyVal := range egressPolicies {
		matchPolicy := func(endpointIP netip.Addr, dstCIDR netip.Prefix, excludedCIDR bool, gwc *gatewayConfig) bool {
			gw0 := gwc.gatewayIP
			gw1 := gwc.gatewayIP1
			activeGW := gwc.activeGW
			if excludedCIDR {
				gw0 = ExcludedCIDRIPv4
				gw1 = netip.IPv4Unspecified()
				activeGW = 0
			} else if activeGW == 0 {
				gw0 = GatewayNotFoundIPv4
				gw1 = netip.IPv4Unspecified()
			}

			return policyKey.Match(endpointIP, dstCIDR) && policyVal.Match(gwc.egressIP, gw0, gw1, activeGW)
		}

		if manager.policyMatches(policyKey.GetSourceIP(), matchPolicy) {
			continue
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SourceIP:        policyKey.GetSourceIP(),
			logfields.DestinationCIDR: policyKey.GetDestCIDR().String(),
			logfields.EgressIP:        policyVal.GetEgressAddr(),
			logfields.GatewayIP:       fmt.Sprintf("%s,%s", policyVal.GetGatewayAddr0(), policyVal.GetGatewayAddr1()),
		})

		if err := manager.policyMap.Delete(policyKey.GetSourceIP(), policyKey.GetDestCIDR()); err != nil {
			logger.WithError(err).Error("Error removing egress gateway policy")
		} else {
			logger.Debug("Egress gateway policy removed")
		}
	}
}

// reconcileReverseMap populates the reverse lookup map (egress_ip → gw0, gw1)
// used by the BPF datapath to redirect reply traffic on non-owner gateways.
func (manager *Manager) reconcileReverseMap() {
	if manager.reverseMap == nil {
		return
	}

	// Collect desired state: egress IP → (gw0, gw1).
	// Only active gateways go in the reverse map. When one gateway
	// is down, the surviving one is compacted to slot 0 so the BPF
	// port-based steering code safely skips (gw1==0).
	desired := make(map[netip.Addr][2]netip.Addr)
	for _, pc := range manager.policyConfigs {
		gwc := &pc.gatewayConfig
		if !gwc.egressIP.IsValid() || gwc.egressIP == EgressIPNotFoundIPv4 {
			continue
		}
		gw0 := GatewayNotFoundIPv4
		gw1 := GatewayNotFoundIPv4
		if gwc.activeGW&egressmap.ActiveGW0 != 0 {
			gw0 = gwc.gatewayIP
		}
		if gwc.activeGW&egressmap.ActiveGW1 != 0 {
			gw1 = gwc.gatewayIP1
		}
		// Compact: if only gw1 is active, move it to slot 0
		if gw0 == GatewayNotFoundIPv4 && gw1 != GatewayNotFoundIPv4 {
			gw0 = gw1
			gw1 = GatewayNotFoundIPv4
		}
		desired[gwc.egressIP] = [2]netip.Addr{gw0, gw1}
	}

	// Update or add entries
	for egressIP, gws := range desired {
		if err := manager.reverseMap.Update(egressIP, gws[0], gws[1]); err != nil {
			log.WithError(err).WithField(logfields.EgressIP, egressIP).
				Error("Error updating egress gateway reverse map")
		}
	}

	// Remove stale entries
	manager.reverseMap.IterateWithCallback(func(key *egressmap.EgressReverseKey4, val *egressmap.EgressReverseVal4) {
		addr := key.EgressIP.Addr()
		if _, ok := desired[addr]; !ok {
			if err := manager.reverseMap.Delete(addr); err != nil {
				log.WithError(err).WithField(logfields.EgressIP, addr).
					Error("Error removing stale egress gateway reverse map entry")
			}
		}
	})
}

// reconcileLocked is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (egress policy map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileLocked() {
	if !manager.allCachesSynced {
		return
	}

	switch {
	// on eventK8sSyncDone we need to update all caches unconditionally as
	// we don't know which k8s events/resources were received during the
	// initial k8s sync
	case manager.eventBitmapIsSet(eventUpdateEndpoint, eventDeleteEndpoint, eventK8sSyncDone):
		manager.updatePoliciesMatchedEndpointIDs()
		fallthrough
	case manager.eventBitmapIsSet(eventAddPolicy, eventDeletePolicy):
		manager.updatePoliciesBySourceIP()
	}

	manager.regenerateGatewayConfigs()

	// Sysctl updates are handled by a reconciler, with the initial update attempting to wait some time
	// for a synchronous reconciliation. Thus these updates are already resilient so in case of failure
	// our best course of action is to log the error and continue with the reconciliation.
	//
	// The rp_filter setting is only important for traffic originating from endpoints on the same host (i.e.
	// egw traffic being forwarded from a local Pod endpoint to the gateway on the same node).
	// Therefore, for the sake of resiliency, it is acceptable for EGW to continue reconciling gatewayConfigs
	// even if the rp_filter setting are failing.
	if err := manager.relaxRPFilter(); err != nil {
		log.WithError(err).Error("Error relaxing rp_filter for gateway interfaces. "+
			"Selected egress gateway interfaces require rp_filter settings to use loose mode (rp_filter=2) for gateway forwarding to work correctly. ",
			"This may cause connectivity issues for egress gateway traffic being forwarded through this node for Pods running on the same host. ")
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingEgressRules()
	manager.removeUnusedEgressRules()
	manager.reconcileReverseMap()

	// Update the prober with current gateway targets so it probes only
	// nodes that are actually selected as gateways.
	manager.updateProberTargets()

	// clear the events bitmap
	manager.eventsBitmap = 0

	manager.reconciliationEventsCount.Add(1)
}
