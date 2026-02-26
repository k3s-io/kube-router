package netpol

import (
	"sigs.k8s.io/knftables"
)

type NetworkPolicyControllerNftables struct {
	NetworkPolicyControllerBase

	nftv4 knftables.Interface
	nftv6 knftables.Interface
}
