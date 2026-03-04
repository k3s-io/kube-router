package netpol

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	v1core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
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

func TestBasicChains(t *testing.T) {
	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", []string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)

	krNetPol.ensureTopLevelChains()
	krNetPol.ensureDefaultNetworkPolicyChain()
	krNetPol.ensureCommonPolicyChain()
	fakeIPv4Itf, ok := krNetPol.knftInterfaces[v1.IPv4Protocol].(*knftables.Fake)
	if !ok {
		t.Fatalf("Expected knftInterfaces[v1.IPv4Protocol] to be of type *knftables.Fake")
	} else {
		ipv4Dump := fakeIPv4Itf.Dump()
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

func TestNetworkPolicyBuilderNft(t *testing.T) {
	port, port1 := intstr.FromInt(30000), intstr.FromInt(34000)
	ingressPort := intstr.FromInt(37000)
	endPort, endPort1 := int32(31000), int32(35000)
	testCases := []tNetpolTestCase{
		{
			name: "Simple Egress Destination Port",
			netpol: tNetpol{name: "simple-egress", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-C23KD7UE4TAT3Y5M dport 30000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress namespace nsA\"\n",
		},
		{
			name: "Simple Ingress/Egress Destination Port",
			netpol: tNetpol{name: "simple-ingress-egress", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
				ingress: []netv1.NetworkPolicyIngressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &ingressPort,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-IDIX352DRLNY3D23 dport 30000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-ingress-egress namespace nsA\"\n" +
				"add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-IDIX352DRLNY3D23 dport 37000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from all sources to dest pods selected by policy name: simple-ingress-egress namespace nsA\"\n",
		},
		{
			name: "Simple Egress Destination Port Range",
			netpol: tNetpol{name: "simple-egress-pr", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port:    &port,
								EndPort: &endPort,
							},
							{
								Port:    &port1,
								EndPort: &endPort1,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-2UTXQIFBI5TAPUCL dport 30000-31000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\"\n" +
				"add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-2UTXQIFBI5TAPUCL dport 34000-35000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\"\n",
		},
		{
			name: "Port > EndPort (invalid condition, should drop endport)",
			netpol: tNetpol{name: "invalid-endport", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port:    &port1,
								EndPort: &endPort,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-N5DQE4SCQ56JEMH7 dport 34000 counter meta mark set meta mark or 0x10000 return comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: invalid-endport namespace nsA\"\n",
		},
	}

	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", []string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	for _, test := range testCases {
		test.netpol.createFakeNetpol(t, netpolInformer)
		netpols, err := krNetPol.buildNetworkPoliciesInfo()
		if err != nil {
			t.Errorf("Problems building policies: %s", err)
		}
		for ipFamily, nft := range krNetPol.knftInterfaces {
			for _, np := range netpols {
				fmt.Print(np.policyType)
				policyChainName := networkPolicyChainName(np.namespace, np.name, "1", ipFamily)

				tx := nft.NewTransaction()

				// Declare (or reset) the policy chain.
				tx.Add(&knftables.Chain{
					Name:    policyChainName,
					Comment: knftables.PtrTo("chain for network policy " + np.namespace + "/" + np.name),
				})
				tx.Flush(&knftables.Chain{Name: policyChainName})

				if np.policyType == kubeEgressPolicyType || np.policyType == kubeBothPolicyType {
					err = krNetPol.processEgressRulesNft(tx, np, "", nil, "1", ipFamily)
					if err != nil {
						t.Errorf("Error syncing the rules: %s", err)
					}
				}
				if np.policyType == kubeIngressPolicyType || np.policyType == kubeBothPolicyType {
					err = krNetPol.processIngressRulesNft(tx, np, "", nil, "1", ipFamily)
					if err != nil {
						t.Errorf("Error syncing the rules: %s", err)
					}
				}
				if err = nft.Run(ctx, tx); err != nil {
					t.Errorf("Error running nftables transaction: %s", err)
				}
			}
			fakeItf, ok := krNetPol.knftInterfaces[ipFamily].(*knftables.Fake)
			if !ok {
				t.Fatalf("Expected knftInterfaces[%v] to be of type *knftables.Fake", ipFamily)
			}
			ipv4Dump := fakeItf.Dump()
			t.Logf("IPv4 rules: %s\n", ipv4Dump)
			if !strings.Contains(ipv4Dump, test.expectedRule) {
				t.Errorf("Expected nftables rules not found in dump for test case %s", test.name)
			}

			key := fmt.Sprintf("%s/%s", test.netpol.namespace, test.netpol.name)
			obj, exists, err := krNetPol.npLister.GetByKey(key)
			if err != nil {
				t.Errorf("Failed to get Netpol from store: %s", err)
			}
			if exists {
				err = krNetPol.npLister.Delete(obj)
				if err != nil {
					t.Errorf("Failed to remove Netpol from store: %s", err)
				}
			}
		}
	}
}

func TestFullPolicySync(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")

	pods := testhelpers.LoadPodList(t, filepath.Join(fixtureDir, "pods.yaml"))
	networkPolicies := testhelpers.LoadNetworkPolicyList(t, filepath.Join(fixtureDir, "networkpolicy.yaml"))
	nodes := testhelpers.LoadNodeList(t, filepath.Join(fixtureDir, "nodes.yaml"))
	namespaces := deriveNamespaces(pods, networkPolicies)

	client := fake.NewSimpleClientset()
	for i := range nodes.Items {
		_, err := client.CoreV1().Nodes().Create(context.Background(), nodes.Items[i].DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}

	config := &options.KubeRouterConfig{
		EnableIPv4:       true,
		EnableIPv6:       true,
		ClusterIPCIDRs:   []string{"10.96.0.0/16", "2001:db8:42:1::/112"},
		HostnameOverride: nodes.Items[0].Name,
		NodePortRange:    "30000-32767",
	}

	informerFactory := informers.NewSharedInformerFactory(client, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()

	ipv4KNftInterface := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	ipv6KNftInterface := knftables.NewFake(knftables.IPv6Family, ipv6Table)

	//Don't forget to create the table before adding chains to it (idempotent).
	tx := ipv4KNftInterface.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv4Table),
	})
	err := ipv4KNftInterface.Run(context.TODO(), tx)
	if err != nil {
		t.Fatalf("nftables: couldn't initialise table %s: %v", ipv4Table, err)
		return
	}
	tx = ipv6KNftInterface.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv6Table),
	})
	err = ipv6KNftInterface.Run(context.TODO(), tx)
	if err != nil {
		t.Fatalf("nftables: couldn't initialise table %s: %v", ipv6Table, err)
		return
	}
	linkQ := utils.NewFakeLocalLinkQuerier(collectNodeIPs(nodes), nil)

	npc, err := NewNetworkPolicyController(
		client,
		config,
		podInformer,
		npInformer,
		nsInformer,
		&sync.Mutex{},
		linkQ,
		nil,
		nil,
		map[v1core.IPFamily]knftables.Interface{
			v1core.IPv4Protocol: ipv4KNftInterface,
			v1core.IPv6Protocol: ipv6KNftInterface,
		},
		true,
	)
	require.NoError(t, err)

	addPodsToInformer(t, podInformer.GetStore(), pods)
	addNetworkPoliciesToInformer(t, npInformer.GetStore(), networkPolicies)
	addNamespacesToInformer(nsInformer.GetStore(), namespaces)

	npc.ensureTopLevelChains()
	npc.ensureDefaultNetworkPolicyChain()
	npc.ensureCommonPolicyChain()

	ipv4Dump := ipv4KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv4Dump)

	netpolInfo, err := npc.buildNetworkPoliciesInfo()
	require.NoError(t, err)

	_, _, err = npc.syncNetworkPolicyChains(netpolInfo, "fixture")
	ipv4Dump = ipv4KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv4Dump)

	ipv6Dump := ipv6KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv6Dump)

	require.NoError(t, err)
	// TODO_TF: add assertions to verify the expected rules are present in the dumps
}
