package main

import (
	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

const chainName = "SIMPLECNI"

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
	addRule := func(ipTables *iptables.IPTables, podCIDR *net.IPNet) error {

		exists, err := ipTables.ChainExists("nat", chainName)
		if err != nil {
			return errors.WithMessagef(err, "failed to check chain exists [%s]", chainName)
		}
		if !exists {
			if err := ipTables.NewChain("nat", chainName); err != nil {
				return errors.WithMessagef(err, "failed to create chain [%s]", chainName)
			}
		}
		if err := ipTables.AppendUnique("nat", chainName, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
			return errors.WithMessagef(err, "failed to enable tcp mss clamping")
		}
		if err := ipTables.AppendUnique("nat", chainName, "-j", "MASQUERADE"); err != nil {
			return errors.WithMessagef(err, "failed to append the nat rule")
		}
		if err := ipTables.AppendUnique("nat", "POSTROUTING", "--src", podCIDR.String(), "-j", chainName); err != nil {
			return errors.WithMessagef(err, "failed to redirect outgoing traffic from [%s]", podCIDR.String())
		}
		if err := ipTables.InsertUnique("nat", chainName, 1, "--dst", podCIDR.String(), "-j", "RETURN"); err != nil {
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

func cleanIptables() error {
	deleteRule := func(ipTables *iptables.IPTables) error {
		if err := ipTables.ClearChain("nat", chainName); err != nil {
			return errors.WithMessagef(err, "failed to clear the chain [%s]", chainName)
		}
		if err := ipTables.DeleteChain("nat", chainName); err != nil {
			return errors.WithMessagef(err, "failed to delete the chain [%s]", chainName)
		}
		return nil
	}
	ipv4Tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return errors.WithMessagef(err, "failed to get ipv4 iptables")
	}
	ipv6Tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return errors.WithMessagef(err, "failed to get ipv6 iptables")
	}
	if err = deleteRule(ipv4Tables); err != nil {
		return errors.WithMessagef(err, "failed to delete ipv4 rules")
	}
	if err = deleteRule(ipv6Tables); err != nil {
		return errors.WithMessagef(err, "failed to delete ipv6 rules")
	}
	return nil
}
