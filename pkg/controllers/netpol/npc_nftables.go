package netpol

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

const (
	ipv4Table = "kube-router-filter-ipv4"
	ipv6Table = "kube-router-filter-ipv6"
)

var chainToHook = map[string]knftables.BaseChainHook{
	"INPUT":   knftables.InputHook,
	"OUTPUT":  knftables.OutputHook,
	"FORWARD": knftables.ForwardHook,
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
}

// Creates custom chains KUBE-NWPLCY-DEFAULT which holds rules for the default network policy. This is applied to
// traffic which is not selected by any network policy and is primarily used to allow traffic that is accepted by
// default.
//
// NOTE: This chain is only targeted by unidirectional network traffic selectors.
func (npc *NetworkPolicyControllerNftables) ensureDefaultNetworkPolicyChain() {
	ctx := context.Background() //TODO_TF: use a context with timeout here
	klog.V(2).Infof("Creating default network policy chains")

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
				"meta mark", "0x1000",
				"return",
			),
		})
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain %s", kubeDefaultNetpolChain)
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
