package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"strings"

	"github.com/jackpal/gateway"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
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
	log.Infof("node name: %s", nodeName)
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

	err = flushIptables(nodePodCIDRs)
	checkError(err)
	fireCh := make(chan struct{})
	go func() {
		for range fireCh {
			// Flush routes when node list changed, nodes are added or removed or modified.
			err := flushRoutes(ctx, nodeName, kubeClient, defaultNIC, clusterPodCIDRs)
			if err != nil {
				log.Errorf("failed to flush router: %+v", err)
			}
		}
	}()
	// Init routes.
	fireCh <- struct{}{}
	for {
		watcher, err := kubeClient.CoreV1().Nodes().Watch(context.Background(), metav1.ListOptions{})
		checkError(err)
		events := watcher.ResultChan()
		for {
			select {
			case e, ok := <-events:
				if ok {
					log.Info("watch channel is closed")
					break
				}
				log.Infof("got event: %s", e.Type)
				fireCh <- struct{}{}
			}
		}
	}
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

func generateCNIConfig(selfNodePodCIDRs []string) (map[string]interface{}, error) {
	var (
		hasV4, hasV6 bool
		podCIDRs     [][]map[string]interface{}
		routes       []map[string]interface{}
	)
	for _, cidr := range selfNodePodCIDRs {
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
