package netpol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
	"sigs.k8s.io/knftables"
)

const (
	ipv4Table = "kube-router-filter-ipv4"
	ipv6Table = "kube-router-filter-ipv6"
)

var chainToHook = map[string]knftables.BaseChainHook{
	kubeInputChainName:   knftables.InputHook,
	kubeOutputChainName:  knftables.OutputHook,
	kubeForwardChainName: knftables.ForwardHook,
}

type NetworkPolicyControllerNftables struct {
	*NetworkPolicyControllerBase

	knftInterfaces map[v1core.IPFamily]knftables.Interface
}

func NewKnftablesInterfaces(ctx context.Context, config *options.KubeRouterConfig) (map[v1core.IPFamily]knftables.Interface, error) {
	nftInterfaces := make(map[v1core.IPFamily]knftables.Interface, 2)
	var err error
	if config.EnableIPv4 {
		nftInterfaces[v1core.IPv4Protocol], err = initTable(ctx, knftables.IPv4Family, ipv4Table)
		if err != nil {
			return nil, err
		}
	}
	if config.EnableIPv6 {
		nftInterfaces[v1core.IPv6Protocol], err = initTable(ctx, knftables.IPv6Family, ipv6Table)
		if err != nil {
			return nil, err
		}
	}
	return nftInterfaces, nil
}

// create a new table and returns the interface to interact with it
func initTable(ctx context.Context, ipFamily knftables.Family, name string) (knftables.Interface, error) {
	nft, err := knftables.New(ipFamily, name)
	if err != nil {
		return nil, fmt.Errorf("no nftables support: %v", err)
	}
	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + name),
	})
	err = nft.Run(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("nftables: couldn't initialise table %s: %v", name, err)
	}
	return nft, nil
}

func (npc *NetworkPolicyControllerNftables) fullPolicySync() {
	npc.mu.Lock()
	defer npc.mu.Unlock()

	healthcheck.SendHeartBeat(npc.healthChan, healthcheck.NetworkPolicyController)
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), syncVersionBase)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		klog.V(1).Infof("sync nftables took %v", endTime)
	}()

	klog.V(1).Infof("Starting sync of nftables with version: %s", syncVersion)

	// ensure kube-router specific top level chains and corresponding rules exist
	npc.ensureTopLevelChains()

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// ensure common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

	networkPoliciesInfo, err := npc.buildNetworkPoliciesInfo()
	if err != nil {
		klog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	_, _, err = npc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync network policy chains: %v", err.Error())
		return
	}
}

func (npc *NetworkPolicyControllerNftables) kNftInterfaceForCIDR(cidr *net.IPNet) (knftables.Interface, error) {
	if netutils.IsIPv4CIDR(cidr) {
		return npc.knftInterfaces[v1core.IPv4Protocol], nil
	}
	if netutils.IsIPv6CIDR(cidr) {
		return npc.knftInterfaces[v1core.IPv6Protocol], nil
	}

	return nil, fmt.Errorf("invalid CIDR")
}

func (npc *NetworkPolicyControllerNftables) ensureTopLevelChains() {
	ctx := context.Background() //TODO_TF: use a context with timeout here
	klog.V(2).Infof("Creating top level input chains")

	for _, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()

		for chain, hook := range chainToHook {
			tx.Add(&knftables.Chain{
				Name:     chain,
				Comment:  knftables.PtrTo("top level " + chain + " chain for kube-router"),
				Type:     knftables.PtrTo(knftables.FilterType),
				Hook:     knftables.PtrTo(hook),
				Priority: knftables.PtrTo(knftables.FilterPriority),
			})
			tx.Flush(&knftables.Chain{
				Name: chain,
			})
		}
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup top level input chains")
		}
	}

	//traffic towards service CIDRs should be allowed to ingress regardless of any network policy, so add rules for that in the top level chains
	if len(npc.serviceClusterIPRanges) > 0 {
		for _, serviceRange := range npc.serviceClusterIPRanges {
			var family v1core.IPFamily
			if serviceRange.IP.To4() != nil {
				family = v1core.IPv4Protocol
			} else {
				family = v1core.IPv6Protocol
			}
			klog.V(2).Infof("Allow traffic to ingress towards Cluster IP Range: %s for family: %s",
				serviceRange.String(), family)
			nftItf, err := npc.kNftInterfaceForCIDR(&serviceRange)
			if err != nil {
				klog.V(2).ErrorS(err, "nftables: couldn't get interface for CIDR", "cidr", serviceRange.String())
				continue
			}
			tx := nftItf.NewTransaction()
			tx.Add(&knftables.Rule{
				Chain: kubeInputChainName,
				Rule: knftables.Concat(
					"ip daddr", serviceRange.String(),
					"counter", "return",
				),
				Comment: knftables.PtrTo("allow traffic to primary/secondary cluster IP range"),
			})
			err = nftItf.Run(ctx, tx)
			if err != nil {
				klog.V(2).ErrorS(err, "nftables: couldn't setup chain for cluster IP range", "cidr", serviceRange.String())
				continue
			}
		}
	} else {
		klog.Fatalf("Primary service cluster IP range is not configured")
	}

	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()

		for _, protocol := range []string{"tcp", "udp"} {
			tx.Add(&knftables.Rule{
				Chain: kubeInputChainName,
				Rule: knftables.Concat(
					"ip",
					"protocol", protocol,
					"fib", "daddr", "type", "local", protocol,
					"dport", npc.serviceNodePortRange,
					"counter", "return",
				),
				Comment: knftables.PtrTo("allow LOCAL " + protocol + " traffic to node ports"),
			})
			klog.V(2).Infof("Allow %s traffic to ingress towards node port range: %s for family: %s",
				protocol, npc.serviceNodePortRange, family)
		}
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: failed to add rules for node port range")
			continue
		}
	}

	for _, externalIPRange := range npc.serviceExternalIPRanges {
		var family v1core.IPFamily
		if externalIPRange.IP.To4() != nil {
			family = v1core.IPv4Protocol
		} else {
			family = v1core.IPv6Protocol
		}
		klog.V(2).Infof("Allow traffic to ingress towards External IP Range: %s for family: %s",
			externalIPRange.String(), family)
		nftItf, err := npc.kNftInterfaceForCIDR(&externalIPRange)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't get interface for CIDR", "cidr", externalIPRange.String())
			continue
		}
		tx := nftItf.NewTransaction()
		tx.Add(&knftables.Rule{
			Chain: kubeInputChainName,
			Rule: knftables.Concat(
				"ip daddr", externalIPRange.String(),
				"counter", "return",
			),
			Comment: knftables.PtrTo("allow traffic to External IP range"),
		})
		err = nftItf.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain for External IP range", "cidr", externalIPRange.String())
			continue
		}
	}

	for _, loadBalancerIPRange := range npc.serviceLoadBalancerIPRanges {
		var family v1core.IPFamily
		if loadBalancerIPRange.IP.To4() != nil {
			family = v1core.IPv4Protocol
		} else {
			family = v1core.IPv6Protocol
		}
		klog.V(2).Infof("Allow traffic to ingress towards LoadBalancer IP Range: %s for family: %s",
			loadBalancerIPRange.String(), family)
		nftItf, err := npc.kNftInterfaceForCIDR(&loadBalancerIPRange)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't get interface for CIDR", "cidr", loadBalancerIPRange.String())
			continue
		}
		tx := nftItf.NewTransaction()
		tx.Add(&knftables.Rule{
			Chain: kubeInputChainName,
			Rule: knftables.Concat(
				"ip daddr", loadBalancerIPRange.String(),
				"counter", "return",
			),
			Comment: knftables.PtrTo("allow traffic to LoadBalancer IP range"),
		})
		err = nftItf.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain for LoadBalancer IP range", "cidr", loadBalancerIPRange.String())
			continue
		}
	}
}

// Creates custom chains KUBE-NWPLCY-DEFAULT which holds rules for the default network policy. This is applied to
// traffic which is not selected by any network policy and is primarily used to allow traffic that is accepted by
// default.
//
// NOTE: This chain is only targeted by unidirectional network traffic selectors.
func (npc *NetworkPolicyControllerNftables) ensureDefaultNetworkPolicyChain() {
	ctx := context.Background() //TODO_TF: use a context with timeout here
	klog.V(2).Infof("Creating default network policy chain")

	for _, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Add(&knftables.Chain{
			Name:    kubeDefaultNetpolChain,
			Comment: knftables.PtrTo(kubeDefaultNetpolChain + " chain for kube-router"),
		})
		tx.Flush(&knftables.Chain{
			Name: kubeDefaultNetpolChain,
		})
		// Start off by marking traffic with an invalid mark so that we can allow list only traffic accepted by a
		// matching policy. Anything that still has 0x10000
		tx.Add(&knftables.Rule{
			Chain: kubeDefaultNetpolChain,
			Rule: knftables.Concat(
				"counter", "meta mark", "set mark", "or", "0x1000",
			),
			Comment: knftables.PtrTo("rule to mark traffic matching a network policy"),
		})
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain %s", kubeDefaultNetpolChain)
			continue
		}
	}
}

func (npc *NetworkPolicyControllerNftables) ensureCommonPolicyChain() {
	ctx := context.Background() //TODO_TF: use a context with timeout here
	klog.V(2).Infof("Creating common policy chains")

	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Add(&knftables.Chain{
			Name:    kubeCommonNetpolChain,
			Comment: knftables.PtrTo(kubeCommonNetpolChain + " chain for kube-router"),
		})
		tx.Flush(&knftables.Chain{
			Name: kubeCommonNetpolChain,
		})
		// ensure statefull firewall drops INVALID state traffic from/to the pod
		// For full context see: https://bugzilla.netfilter.org/show_bug.cgi?id=693
		// The NAT engine ignores any packet with state INVALID, because there's no reliable way to determine what kind of
		// NAT should be performed. So the proper way to prevent the leakage is to drop INVALID packets.
		// In the future, if we ever allow services or nodes to disable conntrack checking, we may need to make this
		// conditional so that non-tracked traffic doesn't get dropped as invalid.
		tx.Add(&knftables.Rule{
			Chain: kubeCommonNetpolChain,
			Rule: knftables.Concat(
				"ct state invalid", "counter", "drop",
			),
			Comment: knftables.PtrTo("rule to drop invalid state for pod"),
		})
		// ensure statefull firewall that permits RELATED,ESTABLISHED traffic from/to the pod
		tx.Add(&knftables.Rule{
			Chain: kubeCommonNetpolChain,
			Rule: knftables.Concat(
				"ct state established,related", "counter", "accept",
			),
			Comment: knftables.PtrTo("rule for stateful firewall for pod"),
		})

		icmpRules := utils.CommonICMPRules(family)
		for _, icmpRule := range icmpRules {
			tx.Add(&knftables.Rule{
				Chain: kubeCommonNetpolChain,
				Rule: knftables.Concat(
					icmpRule.IPTablesProto,
					"type", icmpRule.ICMPType,
					"counter", "accept"),
				Comment: knftables.PtrTo("allow icmp " + icmpRule.ICMPType + " messages"),
			})
		}
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain %s", kubeCommonNetpolChain)
			continue
		}
	}
}

func NewNetworkPolicyControllerNftables(
	npcBase *NetworkPolicyControllerBase, clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	linkQ utils.LocalLinkQuerier,
	knftInterfaces map[v1core.IPFamily]knftables.Interface) (*NetworkPolicyControllerNftables, error) {

	npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: npcBase, knftInterfaces: knftInterfaces}

	if config.EnableIPv4 {
		if !npc.krNode.IsIPv4Capable() {
			return nil, fmt.Errorf("IPv4 was enabled but no IPv4 address was found on node")
		}
		klog.V(2).Infof("IPv4 is enabled")
		// var err error
		// ctx := context.Background() //TODO_TF: use a context with timeout here
		// npc.knftInterfaces = make(map[v1core.IPFamily]knftables.Interface, 2)
		// npc.knftInterfaces[v1core.IPv4Protocol], err = initTable(ctx, knftables.IPv4Family, ipv4Table)
		// if err != nil {
		// 	return nil, err
		// }
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
	}
	if config.EnableIPv6 {
		if !npc.krNode.IsIPv6Capable() {
			return nil, fmt.Errorf("IPv6 was enabled but no IPv6 address was found on node")
		}
		klog.V(2).Infof("IPv6 is enabled")
		// var err error
		// ctx := context.Background() //TODO_TF: use a context with timeout here
		// npc.knftInterfaces[v1core.IPv6Protocol], err = initTable(ctx, knftables.IPv6Family, ipv6Table)
		// if err != nil {
		// 	return nil, err
		// }
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf
	}
	return &npc, nil
}

// ---------------------------------------------------------------------------
// nftables set naming helpers
// ---------------------------------------------------------------------------
// These produce bare names (no "6:" family prefix) because the sets live inside
// a per-IP-family nftables table.

func nftDestinationPodSetName(namespace, policyName string, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + string(ipFamily)))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftSourcePodSetName(namespace, policyName string, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + string(ipFamily)))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedSourcePodSetName(namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedDestinationPodSetName(namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedSourceIPBlockSetName(namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedDestinationIPBlockSetName(namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedIngressNamedPortSetName(namespace, policyName string, ingressRuleNo, namedPortNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		strconv.Itoa(namedPortNo) + string(ipFamily) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedEgressNamedPortSetName(namespace, policyName string, egressRuleNo, namedPortNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		strconv.Itoa(namedPortNo) + string(ipFamily) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

// ---------------------------------------------------------------------------
// nftables set helpers
// ---------------------------------------------------------------------------

// nftAddOrReplaceIPSet declares a named nftables set and flushes+repopulates its elements
// within the given transaction. Set isNet=true for CIDR/subnet entries (interval set).
func (npc *NetworkPolicyControllerNftables) nftAddOrReplaceIPSet(
	tx *knftables.Transaction, setName string, entries []string, ipFamily v1core.IPFamily, isNet bool) {

	setType := "ipv4_addr"
	if ipFamily == v1core.IPv6Protocol {
		setType = "ipv6_addr"
	}
	set := &knftables.Set{
		Name:    setName,
		Type:    setType,
		Comment: knftables.PtrTo("set for network policy"),
	}
	if isNet {
		set.Flags = []knftables.SetFlag{knftables.IntervalFlag}
	}
	tx.Add(set)
	tx.Flush(&knftables.Set{Name: setName})
	for _, entry := range entries {
		tx.Add(&knftables.Element{
			Set: setName,
			Key: []string{entry},
		})
	}
}

// nftAddOrReplaceIPBlockSet declares a named interval nftables set for CIDR ipblock rules.
// entries is the 2-D slice produced by evalIPBlockPeer where each inner slice is one of:
//
//	[cidr, "timeout", "0"]              – include this CIDR
//	[cidr, "timeout", "0", "nomatch"]   – exclude this CIDR (skipped; handled upstream)
func (npc *NetworkPolicyControllerNftables) nftAddOrReplaceIPBlockSet(
	tx *knftables.Transaction, setName string, entries [][]string, ipFamily v1core.IPFamily) {

	setType := "ipv4_addr"
	if ipFamily == v1core.IPv6Protocol {
		setType = "ipv6_addr"
	}
	tx.Add(&knftables.Set{
		Name:    setName,
		Type:    setType,
		Flags:   []knftables.SetFlag{knftables.IntervalFlag},
		Comment: knftables.PtrTo("set for network policy ip block"),
	})
	tx.Flush(&knftables.Set{Name: setName})
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		// Entries tagged utils.OptionNoMatch are "except" CIDRs; skip them here –
		// the caller is responsible for managing an exclusion set if needed.
		if len(entry) >= 4 && entry[3] == utils.OptionNoMatch {
			continue
		}
		tx.Add(&knftables.Element{
			Set: setName,
			Key: []string{entry[0]},
		})
	}
}

// ---------------------------------------------------------------------------
// rule builder
// ---------------------------------------------------------------------------

// appendRuleToPolicyChainNft adds an nftables rule to policyChainName that marks
// matching traffic with 0x10000 and returns, mirroring the iptables MARK+RETURN pair.
func (npc *NetworkPolicyControllerNftables) appendRuleToPolicyChainNft(
	tx *knftables.Transaction, policyChainName, comment,
	srcSetName, dstSetName, protocol, dPort, endDport string, ipFamily v1core.IPFamily) {

	parts := make([]interface{}, 0)

	addrKeyword := "ip"
	if ipFamily == v1core.IPv6Protocol {
		addrKeyword = "ip6"
	}
	if srcSetName != "" {
		parts = append(parts, addrKeyword, "saddr", "@"+srcSetName)
	}
	if dstSetName != "" {
		parts = append(parts, addrKeyword, "daddr", "@"+dstSetName)
	}
	if protocol != "" {
		parts = append(parts, protocol)
	}
	if dPort != "" {
		if endDport != "" {
			parts = append(parts, "dport", dPort+"-"+endDport)
		} else {
			parts = append(parts, "dport", dPort)
		}
	}
	// Mark and return in a single step (equivalent to iptables MARK --set-xmark + RETURN).
	parts = append(parts, "counter meta mark set meta mark or 0x10000 return")

	var commentPtr *string
	if comment != "" {
		commentPtr = knftables.PtrTo(comment)
	}
	tx.Add(&knftables.Rule{
		Chain:   policyChainName,
		Rule:    knftables.Concat(parts...),
		Comment: commentPtr,
	})
}

// ---------------------------------------------------------------------------
// ingress / egress rule processors
// ---------------------------------------------------------------------------

func (npc *NetworkPolicyControllerNftables) processIngressRulesNft(
	tx *knftables.Transaction, policy networkPolicyInfo,
	targetDestPodSetName string, activePolicyIPSets map[string]bool,
	version string, ipFamily v1core.IPFamily) error {

	if policy.ingressRules == nil {
		return nil
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)

	for ruleIdx, ingressRule := range policy.ingressRules {

		if len(ingressRule.srcPods) != 0 {
			srcPodSetName := nftIndexedSourcePodSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[srcPodSetName] = true
			npc.nftAddOrReplaceIPSet(tx, srcPodSetName,
				getIPsFromPods(ingressRule.srcPods, ipFamily), ipFamily, false)

			if len(ingressRule.ports) != 0 {
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						srcPodSetName, targetDestPodSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
			}

			if len(ingressRule.namedPorts) != 0 {
				for epIdx, endPoints := range ingressRule.namedPorts {
					namedPortSetName := nftIndexedIngressNamedPortSetName(policy.namespace,
						policy.name, ruleIdx, epIdx, ipFamily)
					activePolicyIPSets[namedPortSetName] = true
					npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
						endPoints.ips[ipFamily], ipFamily, false)
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						srcPodSetName, namedPortSetName,
						endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
				}
			}

			if len(ingressRule.ports) == 0 && len(ingressRule.namedPorts) == 0 {
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					srcPodSetName, targetDestPodSetName, "", "", "", ipFamily)
			}
		}

		if ingressRule.matchAllSource && !ingressRule.matchAllPorts {
			for _, portProtocol := range ingressRule.ports {
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					"", targetDestPodSetName,
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
			for epIdx, endPoints := range ingressRule.namedPorts {
				namedPortSetName := nftIndexedIngressNamedPortSetName(policy.namespace,
					policy.name, ruleIdx, epIdx, ipFamily)
				activePolicyIPSets[namedPortSetName] = true
				npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
					endPoints.ips[ipFamily], ipFamily, false)
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					"", namedPortSetName,
					endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
			}
		}

		if ingressRule.matchAllSource && ingressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
				"", targetDestPodSetName, "", "", "", ipFamily)
		}

		if len(ingressRule.srcIPBlocks[ipFamily]) != 0 {
			srcIPBlockSetName := nftIndexedSourceIPBlockSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[srcIPBlockSetName] = true
			npc.nftAddOrReplaceIPBlockSet(tx, srcIPBlockSetName, ingressRule.srcIPBlocks[ipFamily], ipFamily)

			if !ingressRule.matchAllPorts {
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						srcIPBlockSetName, targetDestPodSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
				for epIdx, endPoints := range ingressRule.namedPorts {
					namedPortSetName := nftIndexedIngressNamedPortSetName(policy.namespace,
						policy.name, ruleIdx, epIdx, ipFamily)
					activePolicyIPSets[namedPortSetName] = true
					npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
						endPoints.ips[ipFamily], ipFamily, false)
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						srcIPBlockSetName, namedPortSetName,
						endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
				}
			}
			if ingressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					srcIPBlockSetName, targetDestPodSetName, "", "", "", ipFamily)
			}
		}
	}

	return nil
}

func (npc *NetworkPolicyControllerNftables) processEgressRulesNft(
	tx *knftables.Transaction, policy networkPolicyInfo,
	targetSourcePodSetName string, activePolicyIPSets map[string]bool,
	version string, ipFamily v1core.IPFamily) error {

	if policy.egressRules == nil {
		return nil
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)

	for ruleIdx, egressRule := range policy.egressRules {

		if len(egressRule.dstPods) != 0 {
			dstPodSetName := nftIndexedDestinationPodSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[dstPodSetName] = true
			npc.nftAddOrReplaceIPSet(tx, dstPodSetName,
				getIPsFromPods(egressRule.dstPods, ipFamily), ipFamily, false)

			if len(egressRule.ports) != 0 {
				for _, portProtocol := range egressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						targetSourcePodSetName, dstPodSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
			}

			if len(egressRule.namedPorts) != 0 {
				for epIdx, endPoints := range egressRule.namedPorts {
					namedPortSetName := nftIndexedEgressNamedPortSetName(policy.namespace,
						policy.name, ruleIdx, epIdx, ipFamily)
					activePolicyIPSets[namedPortSetName] = true
					npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
						endPoints.ips[ipFamily], ipFamily, false)
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						targetSourcePodSetName, namedPortSetName,
						endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
				}
			}

			if len(egressRule.ports) == 0 && len(egressRule.namedPorts) == 0 {
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, dstPodSetName, "", "", "", ipFamily)
			}
		}

		if egressRule.matchAllDestinations && !egressRule.matchAllPorts {
			for _, portProtocol := range egressRule.ports {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, "",
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
			for _, portProtocol := range egressRule.namedPorts {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, "",
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
		}

		if egressRule.matchAllDestinations && egressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
				targetSourcePodSetName, "", "", "", "", ipFamily)
		}

		if len(egressRule.dstIPBlocks[ipFamily]) != 0 {
			dstIPBlockSetName := nftIndexedDestinationIPBlockSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[dstIPBlockSetName] = true
			npc.nftAddOrReplaceIPBlockSet(tx, dstIPBlockSetName, egressRule.dstIPBlocks[ipFamily], ipFamily)

			if !egressRule.matchAllPorts {
				for _, portProtocol := range egressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
						targetSourcePodSetName, dstIPBlockSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
			}
			if egressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, dstIPBlockSetName, "", "", "", ipFamily)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// syncNetworkPolicyChains
// ---------------------------------------------------------------------------

// syncNetworkPolicyChains is the nftables equivalent of the iptables/ipset implementation.
// For each network policy it creates one nftables chain per IP family, plus named sets
// that hold the matched pod IPs (replacing iptables ipsets).  It returns maps of all
// active chain and set names so the caller can garbage-collect stale objects.
func (npc *NetworkPolicyControllerNftables) syncNetworkPolicyChains(
	networkPoliciesInfo []networkPolicyInfo, version string) (map[string]bool, map[string]bool, error) {

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		}
		klog.V(2).Infof("Syncing network policy chains took %v", endTime)
	}()

	ctx := context.Background()
	activePolicyChains := make(map[string]bool)
	activePolicyIPSets := make(map[string]bool)

	defer func() {
		if npc.MetricsEnabled {
			metrics.ControllerPolicyChains.Set(float64(len(activePolicyChains)))
			metrics.ControllerPolicyIpsets.Set(float64(len(activePolicyIPSets)))
		}
	}()

	for _, policy := range networkPoliciesInfo {
		// Gather current pod IPs for this policy split by IP family.
		currentPodIPs := make(map[v1core.IPFamily][]string)
		for _, pod := range policy.targetPods {
			for _, ip := range pod.ips {
				if netutils.IsIPv4String(ip.IP) {
					currentPodIPs[v1core.IPv4Protocol] = append(currentPodIPs[v1core.IPv4Protocol], ip.IP)
				}
				if netutils.IsIPv6String(ip.IP) {
					currentPodIPs[v1core.IPv6Protocol] = append(currentPodIPs[v1core.IPv6Protocol], ip.IP)
				}
			}
		}

		for ipFamily, nft := range npc.knftInterfaces {
			// One chain per policy per IP family – name is a hash of namespace+name+version+family.
			policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)
			activePolicyChains[policyChainName] = true

			tx := nft.NewTransaction()

			// Declare (or reset) the policy chain.
			tx.Add(&knftables.Chain{
				Name:    policyChainName,
				Comment: knftables.PtrTo("chain for network policy " + policy.namespace + "/" + policy.name),
			})
			tx.Flush(&knftables.Chain{Name: policyChainName})

			if policy.policyType == kubeBothPolicyType || policy.policyType == kubeIngressPolicyType {
				// Destination-pod set – all pods targeted by this policy (used for ingress matching).
				targetDestPodSetName := nftDestinationPodSetName(policy.namespace, policy.name, ipFamily)
				activePolicyIPSets[targetDestPodSetName] = true
				npc.nftAddOrReplaceIPSet(tx, targetDestPodSetName, currentPodIPs[ipFamily], ipFamily, false)

				if err := npc.processIngressRulesNft(tx, policy, targetDestPodSetName,
					activePolicyIPSets, version, ipFamily); err != nil {
					return nil, nil, err
				}
			}

			if policy.policyType == kubeBothPolicyType || policy.policyType == kubeEgressPolicyType {
				// Source-pod set – all pods targeted by this policy (used for egress matching).
				targetSourcePodSetName := nftSourcePodSetName(policy.namespace, policy.name, ipFamily)
				activePolicyIPSets[targetSourcePodSetName] = true
				npc.nftAddOrReplaceIPSet(tx, targetSourcePodSetName, currentPodIPs[ipFamily], ipFamily, false)

				if err := npc.processEgressRulesNft(tx, policy, targetSourcePodSetName,
					activePolicyIPSets, version, ipFamily); err != nil {
					return nil, nil, err
				}
			}

			if err := nft.Run(ctx, tx); err != nil {
				return nil, nil, fmt.Errorf("nftables: failed to sync policy chain %s: %w", policyChainName, err)
			}
		}
	}

	// Garbage-collect stale policy chains.
	for _, nft := range npc.knftInterfaces {
		existingChains, err := nft.List(ctx, "chains")
		if err != nil {
			klog.Warningf("nftables: could not list chains for cleanup: %v", err)
			continue
		}
		tx := nft.NewTransaction()
		anyDeletions := false
		for _, chain := range existingChains {
			if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) &&
				chain != kubeDefaultNetpolChain &&
				chain != kubeCommonNetpolChain &&
				!activePolicyChains[chain] {
				tx.Delete(&knftables.Chain{Name: chain})
				anyDeletions = true
			}
		}
		if anyDeletions {
			if err := nft.Run(ctx, tx); err != nil {
				klog.Warningf("nftables: failed to cleanup stale chains: %v", err)
			}
		}
	}

	// Garbage-collect stale named sets.
	for _, nft := range npc.knftInterfaces {
		existingSets, err := nft.List(ctx, "sets")
		if err != nil {
			klog.Warningf("nftables: could not list sets for cleanup: %v", err)
			continue
		}
		tx := nft.NewTransaction()
		anyDeletions := false
		for _, set := range existingSets {
			if (strings.HasPrefix(set, kubeSourceIPSetPrefix) ||
				strings.HasPrefix(set, kubeDestinationIPSetPrefix)) &&
				!activePolicyIPSets[set] {
				tx.Delete(&knftables.Set{Name: set})
				anyDeletions = true
			}
		}
		if anyDeletions {
			if err := nft.Run(ctx, tx); err != nil {
				klog.Warningf("nftables: failed to cleanup stale sets: %v", err)
			}
		}
	}

	klog.V(2).Infof("nftables chains are synchronized with the network policies.")
	return activePolicyChains, activePolicyIPSets, nil
}
