package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"

	"github.com/jackpal/gateway"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		nodeName       string
		kubeConfigPath string
	)
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODENAME"), "node name")
	flag.StringVar(&kubeConfigPath, "kube-config", "", "kube config path")
	flag.Parse()
	kubeClient := getKubernetesClient(kubeConfigPath)
	ctx := context.Background()
	selfNode, err := kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	checkError(err)
	clusterPodCIDRs, err := getClusterPodCIDRs(kubeClient)
	checkError(err)
	selfPodCIDRs := selfNode.Spec.PodCIDRs
	nodePodCIDRs := make([]*net.IPNet, 0)
	for _, podCIDR := range selfPodCIDRs {
		_, ipNet, err := net.ParseCIDR(podCIDR)
		checkError(err)
		nodePodCIDRs = append(nodePodCIDRs, ipNet)
	}
	conflistFile, err := generateCNIConfig(selfPodCIDRs)
	checkError(err)
	conflistContent, err := json.Marshal(conflistFile)
	checkError(err)
	err = os.WriteFile("/etc/cni/net.d/10-simplecni.conflist", conflistContent, 0o644)
	checkError(err)
	defaultNIC, err := getDefaultNIC()
	checkError(err)
	log.Infof("default nic: %+v", defaultNIC)
	watcher, err := kubeClient.CoreV1().Nodes().Watch(context.Background(), metav1.ListOptions{})
	checkError(err)
	events := watcher.ResultChan()
	err = flushIptables(nodePodCIDRs)
	checkError(err)
	for {
		select {
		case e := <-events:
			log.Infof("event: %+v", e)
			// Flush routes when node list changed, nodes are added or removed or modified.
			err := flushRoutes(ctx, nodeName, kubeClient, defaultNIC, clusterPodCIDRs)
			if err != nil {
				log.Errorf("failed to flush router: %+v", err)
			}
		}
	}
}

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

// getDefaultNIC finds the default NIC of this host.
// The default NIC must have a default gateway.
func getDefaultNIC() (*net.Interface, error) {
	ifIP, err := gateway.DiscoverInterface()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to discover default interface")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to list interfaces")
	}
	for _, nic := range interfaces {
		addrs, err := nic.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch ip := addr.(type) {
			case *net.IPAddr:
				if !ifIP.Equal(ip.IP) {
					continue
				}
			case *net.IPNet:
				if !ifIP.Equal(ip.IP) {
					continue
				}
			default:
				continue
			}
			return &nic, nil
		}
	}
	return nil, errors.WithMessage(err, "failed to find default interface")
}

func generateCNIConfig(podCIDrs []string) (map[string]interface{}, error) {
	var (
		hasV4, hasV6 bool
		podCIDRs     [][]map[string]interface{}
		routes       []map[string]interface{}
	)
	for _, cidr := range podCIDrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse pod cidr [%s]", cidr)
		}
		switch {
		case isIPv4(ipNet.IP):
			hasV4 = true
		case isIPv6(ipNet.IP):
			hasV6 = true
		default:
			continue
		}
		podCIDRs = append(podCIDRs, []map[string]interface{}{{"subnet": cidr}})
	}
	if hasV4 {
		routes = append(routes, map[string]interface{}{"dst": "0.0.0.0/0"})
	}
	if hasV6 {
		routes = append(routes, map[string]interface{}{"dst": "::/0"})
	}
	return map[string]interface{}{
		"name":       "simplecni",
		"cniVersion": "0.3.1",
		"plugins": []map[string]interface{}{
			{
				"type": "ptp", // Create a veth pair for each pod.
				"ipam": map[string]interface{}{
					"type":   "host-local", // Allocate IPs locally within following ranges.
					"ranges": podCIDRs,
					"routes": routes,
				},
			},
			{
				"type":         "portmap", // Essential for HostPort.
				"snat":         true,
				"capabilities": map[string]bool{"portMappings": true},
			},
		},
	}, nil
}

func isIPv4(ipNet net.IP) bool {
	return ipNet.To4() != nil
}

func isIPv6(ipNet net.IP) bool {
	return ipNet.To4() == nil && ipNet.To16() != nil
}

func checkError(err error) {
	if err == nil {
		return
	}
	log.Fatalf("Fatal failure: %v", err)
}

func getKubernetesClient(kubeConfigPath string) kubernetes.Interface {
	var (
		restConfig *rest.Config
		err        error
	)
	if len(kubeConfigPath) > 0 {
		// Use the given kube config.
		log.Debugf("loading kube config from [%s]", kubeConfigPath)
		b, err := os.ReadFile(kubeConfigPath)
		if err != nil {
			log.Fatalf("failed to read kube config [%s]: %v", kubeConfigPath, err)
		}
		config, err := clientcmd.NewClientConfigFromBytes(b)
		if err != nil {
			log.Fatalf("failed to parse kube config [%s]: %v", kubeConfigPath, err)
		}
		restConfig, err = config.ClientConfig()
		if err != nil {
			log.Fatalf("failed to get rest config from kube config [%s]: %v", kubeConfigPath, err)
		}
	} else {
		// Use the in-cluster config.
		log.Debug("loading kube config from in-cluster files")
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			log.Fatalf("failed to get in-cluster config: %v", err)
		}
	}
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("failed to create rest client: %v", err)
	}
	return client
}

type KubeadmClusterConfiguration struct {
	Networking struct {
		PodSubnet string `yaml:"podSubnet"`
	} `yaml:"networking"`
}

func getClusterPodCIDRs(client kubernetes.Interface) ([]*net.IPNet, error) {
	clusterConfig, err := client.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "kubeadm-config", metav1.GetOptions{})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get kubeadm config")
	}
	clusterConfigData := &KubeadmClusterConfiguration{}
	if err := yaml.Unmarshal([]byte(clusterConfig.Data["ClusterConfiguration"]), clusterConfigData); err != nil {
		return nil, errors.WithMessagef(err, "failed to unmarshal kubeadm cluster config")
	}
	podSubnet := clusterConfigData.Networking.PodSubnet
	if len(podSubnet) == 0 {
		return nil, errors.New("kubeadm cluster config has empty pod subnet")
	}

	split := strings.Split(podSubnet, ",")
	podCIDRs := make([]*net.IPNet, 0, len(split))
	for _, s := range split {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse pod subnet from kubeadm config: %s", s)
		}
		podCIDRs = append(podCIDRs, ipNet)
	}
	return podCIDRs, nil
}
