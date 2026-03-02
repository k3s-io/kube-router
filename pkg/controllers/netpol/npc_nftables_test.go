package netpol

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1 "k8s.io/api/core/v1"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

// newUneventfulNfTablesNPC returns new NetworkPolicyController object without any event handler
func newUneventfulNfTablesNPC(podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) *NetworkPolicyControllerNftables {

	npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
	npc.syncPeriod = time.Hour

	npc.filterTableRules = make(map[v1.IPFamily]*bytes.Buffer)
	npc.knftInterfaces = make(map[v1core.IPFamily]knftables.Interface, 2)
	var err error
	ctx := context.Background() //TODO_TF: use a context with timeout here

	//TODO_TF: handle IPv6
	npc.knftInterfaces[v1core.IPv4Protocol] = knftables.NewFake(knftables.IPv4Family, ipv4Table)
	tx := npc.knftInterfaces[v1core.IPv4Protocol].NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv4Table),
	})
	err = npc.knftInterfaces[v1core.IPv4Protocol].Run(ctx, tx)
	if err != nil {
		klog.Errorf("nftables: couldn't initialise table %s: %v", ipv4Table, err)
		return nil
	}

	var buf bytes.Buffer
	npc.filterTableRules[v1.IPv4Protocol] = &buf

	krNode := utils.KRNode{
		NodeName:      "node",
		NodeIPv4Addrs: map[v1.NodeAddressType][]net.IP{v1.NodeInternalIP: {net.IPv4(10, 10, 10, 10)}},
	}
	npc.krNode = &krNode
	npc.serviceClusterIPRanges = []net.IPNet{{IP: net.IPv4(10, 43, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.serviceNodePortRange = "30000-32767"
	npc.serviceExternalIPRanges = []net.IPNet{{IP: net.IPv4(10, 44, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.podLister = podInformer.GetIndexer()
	npc.nsLister = nsInformer.GetIndexer()
	npc.npLister = npInformer.GetIndexer()

	return &npc
}

func TestXxx(t *testing.T) {
	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", []string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	// for _, test := range testCases {
	// 	test.netpol.createFakeNetpol(t, netpolInformer)
	// }
	// netpols, err := krNetPol.buildNetworkPoliciesInfo()
	// if err != nil {
	// 	t.Errorf("Problems building policies")
	// }

	krNetPol.ensureTopLevelChains()
	krNetPol.ensureDefaultNetworkPolicyChain()
	krNetPol.ensureCommonPolicyChain()
	fakeIPv4Itf, ok := krNetPol.knftInterfaces[v1.IPv4Protocol].(*knftables.Fake)
	if !ok {
		t.Fatalf("Expected knftInterfaces[v1.IPv4Protocol] to be of type *knftables.Fake")
	} else {
		ipv4Dump := fakeIPv4Itf.Dump()
		t.Logf("Dumped rules:\n%s", ipv4Dump)
		if !strings.Contains(ipv4Dump, "add table ip kube-router-filter-ipv4 { comment \"rules for kube-router-filter-ipv4\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-FORWARD { type filter hook forward priority 0 ; comment \"top level KUBE-ROUTER-FORWARD chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT { type filter hook input priority 0 ; comment \"top level KUBE-ROUTER-INPUT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-OUTPUT { type filter hook output priority 0 ; comment \"top level KUBE-ROUTER-OUTPUT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip daddr 10.43.0.0/16 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip protocol tcp fib daddr type local tcp dport 30000-32767 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip protocol udp fib daddr type local udp dport 30000-32767 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip daddr 10.44.0.0/16 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-DEFAULT { comment \"KUBE-NWPLCY-DEFAULT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-DEFAULT counter meta mark set mark or 0x1000") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON { comment \"KUBE-NWPLCY-COMMON chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state invalid counter drop") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state invalid counter drop") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state established,related counter") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type echo-request counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type destination-unreachable counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type time-exceeded counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
	}

}
