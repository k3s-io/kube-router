package netpol

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"k8s.io/klog/v2"

	v1core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-ROUTER-INPUT"
	kubeForwardChainName         = "KUBE-ROUTER-FORWARD"
	kubeOutputChainName          = "KUBE-ROUTER-OUTPUT"
	kubeDefaultNetpolChain       = "KUBE-NWPLCY-DEFAULT"
	kubeCommonNetpolChain        = "KUBE-NWPLCY-COMMON"

	kubeIngressPolicyType = "ingress"
	kubeEgressPolicyType  = "egress"
	kubeBothPolicyType    = "both"

	syncVersionBase = 10
)

var (
	defaultChains = map[string]string{
		"INPUT":   kubeInputChainName,
		"FORWARD": kubeForwardChainName,
		"OUTPUT":  kubeOutputChainName,
	}
)

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through filter table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

type NetworkPolicyController interface {
	Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup)
	RequestFullSync()
	fullPolicySync()
	ensureTopLevelChains()
	ensureDefaultNetworkPolicyChain()
	ensureCommonPolicyChain()

	buildNetworkPoliciesInfo() ([]networkPolicyInfo, error)
	syncNetworkPolicyChains(networkPoliciesInfo []networkPolicyInfo,
		version string) (map[string]bool, map[string]bool, error)

	PodEventHandler() cache.ResourceEventHandler
	NamespaceEventHandler() cache.ResourceEventHandler
	NetworkPolicyEventHandler() cache.ResourceEventHandler
}

// NetworkPolicyController struct to hold information required by NetworkPolicyController
type NetworkPolicyControllerBase struct {
	krNode                      utils.NodeIPAndFamilyAware
	serviceClusterIPRanges      []net.IPNet
	serviceExternalIPRanges     []net.IPNet
	serviceLoadBalancerIPRanges []net.IPNet
	serviceNodePortRange        string
	mu                          sync.Mutex
	syncPeriod                  time.Duration
	MetricsEnabled              bool
	healthChan                  chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan         chan struct{}
	ipsetMutex                  *sync.Mutex

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	podEventHandler           cache.ResourceEventHandler
	namespaceEventHandler     cache.ResourceEventHandler
	networkPolicyEventHandler cache.ResourceEventHandler
}

func (npc *NetworkPolicyControllerBase) PodEventHandler() cache.ResourceEventHandler {
	return npc.podEventHandler
}

func (npc *NetworkPolicyControllerBase) NamespaceEventHandler() cache.ResourceEventHandler {
	return npc.namespaceEventHandler
}

func (npc *NetworkPolicyControllerBase) NetworkPolicyEventHandler() cache.ResourceEventHandler {
	return npc.networkPolicyEventHandler
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name        string
	namespace   string
	podSelector labels.Selector

	// set of pods matching network policy spec podselector label selector
	targetPods map[string]podInfo

	// whitelist ingress rules from the network policy spec
	ingressRules []ingressRule

	// whitelist egress rules from the network policy spec
	egressRules []egressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

// internal structure to represent Pod
type podInfo struct {
	ip        string
	ips       []v1core.PodIP
	name      string
	namespace string
	labels    map[string]string
}

// internal structure to represent NetworkPolicyIngressRule in the spec
type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	namedPorts     []endPoints
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    map[v1core.IPFamily][][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          map[v1core.IPFamily][][]string
}

type protocolAndPort struct {
	protocol string
	port     string
	endport  string
}

type endPoints struct {
	ips map[v1core.IPFamily][]string
	protocolAndPort
}

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

// Run runs forever till we receive notification on stopCh
func (npc *NetworkPolicyControllerIptables) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	npc.ensureTopLevelChains()

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// setup common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

	// Full syncs of the network policy controller take a lot of time and can only be processed one at a time,
	// therefore, we start it in it's own goroutine and request a sync through a single item channel
	klog.Info("Starting network policy controller full sync goroutine")
	wg.Add(1)
	go func(fullSyncRequest <-chan struct{}, stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			default:
			}
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			case <-fullSyncRequest:
				klog.V(3).Info("Received request for a full sync, processing")
				npc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(npc.fullSyncRequestChan, stopCh, wg)

	// loop forever till notified to stop on stopCh
	for {
		klog.V(1).Info("Requesting periodic sync of iptables to reflect network policies")
		npc.RequestFullSync()
		select {
		case <-stopCh:
			klog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (npc *NetworkPolicyControllerIptables) RequestFullSync() {
	select {
	case npc.fullSyncRequestChan <- struct{}{}:
		klog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		klog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex, linkQ utils.LocalLinkQuerier,
	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler,
	ipSetHandlers map[v1core.IPFamily]utils.IPSetHandler,
	useNftables bool,
) (NetworkPolicyController, error) {
	if useNftables {
		return nil, fmt.Errorf("nftables is not currently supported for network policy controller")
	} else {
		return NewNetworkPolicyControllerIptables(clientset, config, podInformer, npInformer, nsInformer, ipsetMutex, linkQ, iptablesCmdHandlers, ipSetHandlers)
	}
}
