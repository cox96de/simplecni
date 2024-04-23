package main

import (
	"context"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func flushRoutes(ctx context.Context, selfNode string, kubeClient kubernetes.Interface, nic *net.Interface,
	clusterPodCIDRs []*net.IPNet,
) error {
	nodeList, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.WithMessagef(err, "failed to list node list")
	}
	peerNodes := make([]*corev1.Node, 0, len(nodeList.Items)-1)
	for _, node := range nodeList.Items {
		node := node
		if node.Name == selfNode {
			continue
		}
		peerNodes = append(peerNodes, &node)
	}
	link, err := netlink.LinkByName(nic.Name)
	if err != nil {
		return errors.WithMessagef(err, "failed to get link by name [%s]", nic.Name)
	}
	rs, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return errors.WithMessagef(err, "failed to list route list")
	}
	// Filter routes that are in cluster pod CIDRs.
	// The route might be created by other CNI plugins or previous execution.
	// If it is not affect route, it's better to delete.
	// If it is affect route, keep it.
	clusterRouter := filterClusterRouter(rs, clusterPodCIDRs)
	for _, node := range peerNodes {
		var (
			ipv4 net.IP
			ipv6 net.IP
		)
		for _, address := range node.Status.Addresses {
			if address.Type != corev1.NodeInternalIP {
				continue
			}
			if isIPv4(net.ParseIP(address.Address)) && ipv4 == nil {
				ipv4 = net.ParseIP(address.Address)
			}
			if isIPv6(net.ParseIP(address.Address)) && ipv6 == nil {
				ipv6 = net.ParseIP(address.Address)
			}
		}
		for _, podCIDR := range node.Spec.PodCIDRs {
			_, peerNodeCIDR, err := net.ParseCIDR(podCIDR)
			if err != nil {
				log.Errorf("failed to parse pod cidr [%s]: %+v", podCIDR, err)
				continue
			}
			var nodeIP net.IP
			switch {
			case isIPv4(peerNodeCIDR.IP):
				if ipv4 == nil {
					log.Errorf("failed to find ipv4 address of node [%s]", node.Name)
					continue
				}
				nodeIP = ipv4
			case isIPv6(peerNodeCIDR.IP):
				if ipv6 == nil {
					log.Errorf("failed to find ipv6 address of node [%s]", node.Name)
					continue
				}
				nodeIP = ipv6
			default:
				log.Errorf("unknown ip version: %+v", peerNodeCIDR.IP)
				continue
			}
			r := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       peerNodeCIDR,
				Gw:        nodeIP,
			}
			log.Infof("node ip: %+v", nodeIP)
			// Identical to: ip route add <dst> via <nodeIP> dev <link>
			if r, ok := clusterRouter[r.Dst.String()]; ok {
				// The route rule is already exists.
				// Skip to create that.
				if r.Gw.Equal(nodeIP) {
					delete(clusterRouter, r.Dst.String())
					continue
				}
			}
			log.Infof("add route %+v", r)
			if err = netlink.RouteAdd(r); err != nil {
				log.Errorf("failed to add route [%+v]: %+v", r, err)
				continue
			}

		}
	}
	// Remote all unknown routes.
	for _, route := range clusterRouter {
		log.Infof("delete route %+v", route)
		if err := netlink.RouteDel(&route); err != nil {
			log.Errorf("failed to delete route [%+v]: %+v", route, err)
			continue
		}
	}
	return nil
}

func filterClusterRouter(rs []netlink.Route, clusterPodCIDRs []*net.IPNet) map[string]netlink.Route {
	routes := map[string]netlink.Route{}
	for _, r := range rs {
		if r.Dst == nil {
			continue
		}
		for _, cidr := range clusterPodCIDRs {
			if !cidr.Contains(r.Dst.IP) {
				continue
			}
			_, ok := routes[r.Dst.String()]
			if ok {
				log.Errorf("duplicate route: %+v", r)
			} else {
				routes[r.Dst.String()] = r
			}
		}
	}
	return routes
}

func cleanRoutes(nic *net.Interface, clusterPodCIDRs []*net.IPNet) error {
	link, err := netlink.LinkByName(nic.Name)
	if err != nil {
		return errors.WithMessagef(err, "failed to get link by name [%s]", nic.Name)
	}
	rs, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return errors.WithMessagef(err, "failed to list route list")
	}
	// Filter routes that are in cluster pod CIDRs.
	clusterRouter := filterClusterRouter(rs, clusterPodCIDRs)
	// Remote all unknown routes.
	for _, route := range clusterRouter {
		log.Infof("delete route %+v", route)
		if err := netlink.RouteDel(&route); err != nil {
			log.Errorf("failed to delete route [%+v]: %+v", route, err)
			continue
		}
	}
	return nil
}
