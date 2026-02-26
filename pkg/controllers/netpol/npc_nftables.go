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

func NewNetworkPolicyControllerNftables(
	npcBase *NetworkPolicyControllerBase, clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	linkQ utils.LocalLinkQuerier) (*NetworkPolicyControllerNftables, error) {

	npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: npcBase}
	if config.EnableIPv4 {
		if !npc.krNode.IsIPv4Capable() {
			return nil, fmt.Errorf("IPv4 was enabled but no IPv4 address was found on node")
		}
		klog.V(2).Infof("IPv4 is enabled")
		var err error
		ctx := context.Background() //TODO_TF: use a context with timeout here
		npc.knftInterfaces = make(map[v1core.IPFamily]knftables.Interface, 2)
		npc.knftInterfaces[v1core.IPv4Protocol], err = initTable(ctx, knftables.IPv4Family, ipv4Table)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
	}
	if config.EnableIPv6 {
		if !npc.krNode.IsIPv6Capable() {
			return nil, fmt.Errorf("IPv6 was enabled but no IPv6 address was found on node")
		}
		klog.V(2).Infof("IPv6 is enabled")
		var err error
		ctx := context.Background() //TODO_TF: use a context with timeout here
		npc.knftInterfaces[v1core.IPv6Protocol], err = initTable(ctx, knftables.IPv6Family, ipv6Table)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf
	}
	return &npc, nil
}
