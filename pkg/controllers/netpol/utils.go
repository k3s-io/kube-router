package netpol

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	klog "k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

const (
	PodCompleted api.PodPhase = "Completed"
)

var (
	stringSuffixes = sets.NewString("second", "minute", "hour", "day", "s", "m", "h", "d")
)

// isPodUpdateNetPolRelevant checks the attributes that we care about for building NetworkPolicies on the host and if it
// finds a relevant change, it returns true otherwise it returns false. The things we care about for NetworkPolicies:
//  1. Is the phase of the pod changing? (matters for catching completed, succeeded, or failed jobs)
//  2. Is the pod IP changing? (changes how the network policy is applied to the host)
//  3. Is the pod's host IP changing? (should be caught in the above, with the CNI kube-router runs with but we check
//     this as well for sanity)
//  4. Is a pod's label changing? (potentially changes which NetworkPolicies select this pod)
func isPodUpdateNetPolRelevant(oldPod, newPod *api.Pod) bool {
	return newPod.Status.Phase != oldPod.Status.Phase ||
		newPod.Status.PodIP != oldPod.Status.PodIP ||
		!reflect.DeepEqual(newPod.Status.PodIPs, oldPod.Status.PodIPs) ||
		newPod.Status.HostIP != oldPod.Status.HostIP ||
		!reflect.DeepEqual(newPod.Labels, oldPod.Labels)
}

func isNetPolActionable(pod *api.Pod) bool {
	return !isFinished(pod) && pod.Status.PodIP != "" && !pod.Spec.HostNetwork
}

func isFinished(pod *api.Pod) bool {
	//nolint:exhaustive // We don't care about PodPending, PodRunning, PodUnknown here as we want those to fall
	// into the false case
	switch pod.Status.Phase {
	case api.PodFailed, api.PodSucceeded, PodCompleted:
		return true
	}
	return false
}

func validateNodePortRange(nodePortOption string) (string, error) {
	const portBitSize = 16

	nodePortValidator := regexp.MustCompile(`^([0-9]+)[:-]([0-9]+)$`)
	if matched := nodePortValidator.MatchString(nodePortOption); !matched {
		return "", fmt.Errorf(
			"failed to parse node port range given: '%s' please see specification in help text", nodePortOption)
	}
	matches := nodePortValidator.FindStringSubmatch(nodePortOption)
	if len(matches) != 3 {
		return "", fmt.Errorf("could not parse port number from range given: '%s'", nodePortOption)
	}
	port1, err := strconv.ParseUint(matches[1], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse first port number from range given: '%s'", nodePortOption)
	}
	port2, err := strconv.ParseUint(matches[2], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse second port number from range given: '%s'", nodePortOption)
	}
	if port1 >= port2 {
		return "", fmt.Errorf("port 1 is greater than or equal to port 2 in range given: '%s'", nodePortOption)
	}
	return fmt.Sprintf("%d:%d", port1, port2), nil
}

func getIPsFromPods(pods []podInfo, family api.IPFamily) []string {
	var ips []string
	for _, pod := range pods {
		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch family {
		case api.IPv4Protocol:
			ip, err := getPodIPv4Address(pod)
			if err != nil {
				klog.Warningf("Could not get IPv4 addresses of all pods: %v", err)
				continue
			}
			ips = append(ips, ip)
		case api.IPv6Protocol:
			ip, err := getPodIPv6Address(pod)
			if err != nil {
				klog.Warningf("Could not get IPv6 addresses of all pods: %v", err)
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

func (npc *NetworkPolicyController) createGenericHashIPSet(
	ipsetName, hashType string, ips []string, ipFamily api.IPFamily) {
	setEntries := make([][]string, 0)
	for _, ip := range ips {
		setEntries = append(setEntries, []string{ip, utils.OptionTimeout, "0"})
	}
	npc.ipSetHandlers[ipFamily].RefreshSet(ipsetName, setEntries, hashType)
}

// createPolicyIndexedIPSet creates a policy based ipset and indexes it as an active ipset
func (npc *NetworkPolicyController) createPolicyIndexedIPSet(
	activePolicyIPSets map[string]bool, ipsetName, hashType string, ips []string, ipFamily api.IPFamily) {
	activePolicyIPSets[ipsetName] = true
	npc.createGenericHashIPSet(ipsetName, hashType, ips, ipFamily)
}

// createPodWithPortPolicyRule handles the case where port details are provided by the ingress/egress rule and creates
// an iptables rule that matches on both the source/dest IPs and the port
func (npc *NetworkPolicyController) createPodWithPortPolicyRule(ports []protocolAndPort,
	policy networkPolicyInfo, policyName string, srcSetName string, dstSetName string, ipFamily api.IPFamily) error {
	for _, portProtocol := range ports {
		comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
			policy.name + " namespace " + policy.namespace
		if err := npc.appendRuleToPolicyChain(policyName, comment, srcSetName, dstSetName, portProtocol.protocol,
			portProtocol.port, portProtocol.endport, ipFamily, policy); err != nil {
			return err
		}
	}
	return nil
}

func getPodIPv6Address(pod podInfo) (string, error) {
	for _, ip := range pod.ips {
		if netutils.IsIPv6String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("pod %s:%s has no IPv6Address, available addresses: %s",
		pod.namespace, pod.name, pod.ips)
}

func getPodIPv4Address(pod podInfo) (string, error) {
	for _, ip := range pod.ips {
		if netutils.IsIPv4String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("pod %s:%s has no IPv4Address, available addresses: %s",
		pod.namespace, pod.name, pod.ips)
}

func getPodIPForFamily(pod podInfo, ipFamily api.IPFamily) (string, error) {
	//nolint:exhaustive // we don't need exhaustive searching for IP Families
	switch ipFamily {
	case api.IPv4Protocol:
		if ip, err := getPodIPv4Address(pod); err != nil {
			return "", err
		} else {
			return ip, nil
		}
	case api.IPv6Protocol:
		if ip, err := getPodIPv6Address(pod); err != nil {
			return "", err
		} else {
			return ip, nil
		}
	}

	return "", fmt.Errorf("did not recognize IP Family for pod: %s:%s family: %s", pod.namespace, pod.name,
		ipFamily)
}

func ipSetName(setName string, ipFamily api.IPFamily) string {
	if ipFamily == api.IPv4Protocol {
		return utils.IPSetName(setName, false)
	} else {
		return utils.IPSetName(setName, true)
	}
}

// safeJoin joins the namespace and name, ensuring that the result is less than or equal to 48 characters
func safeJoin(namespace string, name string) string {
	const minLen, maxLen = 24, 48
	if (len(namespace) + len(name)) < maxLen {
		return namespace + "/" + name
	}

	// We must create at least one substring
	if len(namespace) < minLen {
		lengthSubString := (maxLen - len(namespace) - 1)
		return namespace + "/" + name[0:lengthSubString]
	}

	if len(name) < minLen {
		lengthSubString := (maxLen - len(name) - 1)
		return namespace[0:lengthSubString] + "/" + name
	}

	// If we arrive here, both are over 24 characters
	return namespace[0:23] + "/" + name[0:23]
}

// getIptablesNFlogLimit reads the annotations setting the nflog limit and limit-burst config
// "kube-router.io/netpol-nflog-limit" and "kube-router.io/netpol-nflog-limit-burst"
func getIptablesNFlogLimit(annotations map[string]string) (string, string) {
	defaultLimit := "10/minute"
	defaultLimitBurst := "10"

	limit, ok := annotations["kube-router.io/netpol-nflog-limit"]
	if !ok {
		limit = defaultLimit
	}

	limitBurst, ok := annotations["kube-router.io/netpol-nflog-limit-burst"]
	if !ok {
		limitBurst = defaultLimitBurst
	}

	if !areNFlogParamsCorrect(limit, limitBurst) {
		klog.Warning("Network Policy annotations are wrong, default values will be used. Check the docs for more information")
		return defaultLimit, defaultLimitBurst
	}

	return limit, limitBurst
}

// areNFlogParamsCorrect verifies that the nflog parameters are correct
//   - kube-router.io/netpol-nflog-limit must be an integer, with an optional "/second", "/minute", "/hour", "/day"
//     or the first character of each time unit
//   - kube-router.io/netpol-nflog-limit-burst must be an integer
func areNFlogParamsCorrect(limit string, limitBurst string) bool {

	// If limit does not set a time unit, check if limit and limitBurst are integers
	param := strings.Split(limit, "/")
	if len(param) == 1 {
		if isInteger(param[0]) && isInteger(limitBurst) {
			return true
		}
	}

	// If limit sets a time unit, check if it is among the supported ones
	if len(param) == 2 {
		if stringSuffixes.Has(param[1]) {
			// If the time unit is supported, check that limit and limitBurst are integers
			if isInteger(param[0]) && isInteger(limitBurst) {
				return true
			}
		}
	}

	return false
}

// isInteger returns true if the passed value is an integer
func isInteger(x string) bool {
	if _, err := strconv.Atoi(x); err == nil {
		return true
	}
	return false
}
