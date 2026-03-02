package netpol

import (
	"bytes"
	"context"
	"fmt"
	"net"

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
