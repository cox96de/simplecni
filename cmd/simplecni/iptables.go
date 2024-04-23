package main

import (
	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

// flushIptables flushes the iptables rules and adds the rules for the pod CIDRs of the node.
// The rules to enable NAT.
func flushIptables(nodePodCIDRs []*net.IPNet) error {
	ipv4Tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return errors.WithMessagef(err, "failed to get ipv4 iptables")
	}
	ipv6Tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return errors.WithMessagef(err, "failed to get ipv6 iptables")
	}
	addRule := func(ipv4Tables *iptables.IPTables, podCIDR *net.IPNet) error {
		chainName := "SIMPLECNI"
		exists, err := ipv4Tables.ChainExists("nat", chainName)
		if err != nil {
			return errors.WithMessagef(err, "failed to check chain exists [%s]", chainName)
		}
		if !exists {
			if err := ipv4Tables.NewChain("nat", chainName); err != nil {
				return errors.WithMessagef(err, "failed to create chain [%s]", chainName)
			}
		}
		if err := ipv4Tables.AppendUnique("nat", chainName, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
			return errors.WithMessagef(err, "failed to enable tcp mss clamping")
		}
		if err := ipv4Tables.AppendUnique("nat", chainName, "-j", "MASQUERADE"); err != nil {
			return errors.WithMessagef(err, "failed to append the nat rule")
		}
		if err := ipv4Tables.AppendUnique("nat", "POSTROUTING", "--src", podCIDR.String(), "-j", chainName); err != nil {
			return errors.WithMessagef(err, "failed to redirect outgoing traffic from [%s]", podCIDR.String())
		}
		if err := ipv4Tables.InsertUnique("nat", chainName, 1, "--dst", podCIDR.String(), "-j", "RETURN"); err != nil {
			return errors.WithMessagef(err, "failed to add nat exclusion rule for [%s]", podCIDR.String())
		}
		return nil
	}
	for _, podCIDR := range nodePodCIDRs {
		switch {
		case isIPv4(podCIDR.IP):
			if err := addRule(ipv4Tables, podCIDR); err != nil {
				return errors.WithMessagef(err, "failed to add ipv4 rule for [%s]", podCIDR.String())
			}
		case isIPv6(podCIDR.IP):
			if err := addRule(ipv6Tables, podCIDR); err != nil {
				return errors.WithMessagef(err, "failed to add ipv6 rule for [%s]", podCIDR.String())
			}
		}
	}
	return nil
}
