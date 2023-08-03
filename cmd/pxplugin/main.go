package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/portworx/sched-ops/k8s/core"
	"github.com/portworx/windows-csi-driver/pkg/common"
	csicommon "github.com/portworx/windows-csi-driver/pkg/csi-common"
	pwx "github.com/portworx/windows-csi-driver/pkg/portworx"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
)

func init() {
	klog.InitFlags(nil)
}

var (
	endpoint                      = flag.String("endpoint", "unix://tmp/csi.sock", "CSI endpoint")
	nodeID                        = flag.String("nodeid", "", "node id")
	driverName                    = flag.String("drivername", common.DefaultDriverName, "name of the driver")
	ver                           = flag.Bool("ver", false, "Print the version and exit.")
	metricsAddress                = flag.String("metrics-address", "0.0.0.0:29644", "export the metrics")
	kubeconfig                    = flag.String("kubeconfig", "", "Absolute path to the kubeconfig file. Required only when running out of cluster.")
	enableGetVolumeStats          = flag.Bool("enable-get-volume-stats", true, "allow GET_VOLUME_STATS on agent node")
	removeSMBMappingDuringUnmount = flag.Bool("remove-smb-mapping-during-unmount", true, "remove SMBMapping during unmount on Windows node")
	workingMountDir               = flag.String("working-mount-dir", "/tmp", "working directory for provisioner to mount smb shares temporarily")
	mode                          = flag.String("mode", "nfs", "operational mode, one of iscsi/smb/nfs. default nfs")
)

func main() {

	flag.Parse()
	if *ver {
		info, err := pwx.GetVersionYAML(*driverName)
		if err != nil {
			klog.Fatalln(err)
		}
		fmt.Println(info)
		os.Exit(0)
	}
	if *nodeID == "" {
		// nodeid is not needed in controller component
		klog.Warning("nodeid is empty")
	}
	var debug = false
	if debug {
		displayClusterInformation()
	}

	modeval, err := common.ParseDriverMode(*mode)
	if err != nil {
		klog.Fatalln(err)
	}

	exportMetrics()
	handle(modeval)
	os.Exit(0)
}

func displayClusterInformation() {
	klog.V(2).Infof("Logging Cluster Information")

	var gRpcPort string
	svc, err := core.Instance().GetService("portworx-service", "kube-system")
	if err != nil {
		klog.V(2).Infof("Failed to get portworx service, err [%v]", err)
		gRpcPort = "0"
	} else {
		for _, svcPort := range svc.Spec.Ports {
			if svcPort.Name == "px-sdk" {
				targetPort := svcPort.TargetPort
				if targetPort.Type == intstr.String {
					gRpcPort = targetPort.StrVal
				} else {
					gRpcPort = fmt.Sprintf("%d", targetPort.IntValue())
				}
			}
		}
	}

	nodes, errnodes := core.Instance().GetNodes()
	if errnodes != nil {
		klog.V(2).Infof("Getting Cluster information failed %v", errnodes)
	} else {
		var retVal string
		var ipAdded bool
		for _, n := range nodes.Items {
			nodeLabels := make(map[string]string)
			for k, v := range n.GetLabels() {
				nodeLabels[k] = v
			}
			for k, v := range n.GetAnnotations() {
				nodeLabels[k] = v
			}
			v, ok := nodeLabels["beta.kubernetes.io/os"]
			if ok && v == "linux" {
				klog.V(2).Infof("Found a linux node: [%s]", n.GetName())
				//csi, ok := nodeLabels["csi.volume.kubernetes.io/nodeid"]
				csi, ok := nodeLabels["node-role.kubernetes.io/worker"]
				if ok {
					klog.V(2).Infof("Found a linux node: [%s] role [%s]", n.GetName(), csi)
					ipfound := false
					var ip string
					for _, addr := range n.Status.Addresses {
						switch addr.Type {
						case corev1.NodeInternalIP:
							ip = addr.Address
							ipfound = true
							break
						}
						if ipfound {
							break
						}
					}
					if ipfound && ipAdded {
						retVal = fmt.Sprintf("%s %s:%s", retVal, ip, gRpcPort)
					} else if ipfound {
						ipAdded = true
						retVal = fmt.Sprintf("%s:%s", ip, gRpcPort)
					}
				}
			}
		}
		klog.V(2).Infof("Node in PWX Cluster [%s]", retVal)
		parts := strings.Split(retVal, " ")
		i := 0
		for i < len(parts) {
			klog.V(2).Infof("Parts[%d]: %s", i, parts[i])
			i++
		}
	}
	klog.V(2).Infof("Logging Cluster Information Complete")

	klog.V(2).Infof("Populating by reading file")
	bytearr, err := ioutil.ReadFile("C:\\var\\tmp\\data")
	if err != nil {
		klog.V(2).Infof("ReadFile Failed: [%v]", err)
	} else {
		nodeInformation := string(bytearr)
		parts := strings.Split(nodeInformation, " ")
		klog.V(2).Infof("NodeInformation [%s]: len of parts[%d]", nodeInformation, len(parts))
		i := 0
		for i < len(parts) {
			klog.V(2).Infof("Parts[%d]: %s", i, parts[i])
			i++
		}
	}
}

func handle(modeVal common.DriverModeFlag) {
	versionMeta, err := pwx.GetVersionYAML(*driverName)
	if err != nil {
		klog.Fatalf("%v", err)
	}

	klog.V(2).Infof("\nDRIVER INFORMATION[mode %v]:\n-------------------\n%s\n\nStreaming logs below:",
		modeVal, versionMeta)

	driverOptions := common.DriverOptions{
		NodeID:     *nodeID,
		DriverName: *driverName,
		Mode:       modeVal,
		Endpoint:   *endpoint,
		WorkDir:    *workingMountDir,
	}
	driverOptions.SmbOpts.RemoveSMBMappingDuringUnmount = *removeSMBMappingDuringUnmount
	driverOptions.SmbOpts.WorkingMountDir = *workingMountDir

	driver := pwx.NewDriver(*driverName, pwx.DriverVersion(), &driverOptions)

	// SmbDriver or IscsiDriver shall be initialized and run based on passed mode
	driver.Init()

	s := csicommon.NewNonBlockingGRPCServer()

	ctrlSrv := driver.GetControllerServer()
	identitySrv := driver.GetIdentityServer()
	nodeSrv := driver.GetNodeServer()
	testMode := false

	// portworx plugin Driver d only act as NodeServer
	s.Start(*endpoint, identitySrv, ctrlSrv, nodeSrv, testMode)
	s.Wait()
}

func exportMetrics() {
	l, err := net.Listen("tcp", *metricsAddress)
	if err != nil {
		klog.Warningf("failed to get listener for metrics endpoint: %v", err)
		return
	}
	serve(context.Background(), l, serveMetrics)
}

func serve(ctx context.Context, l net.Listener, serveFunc func(net.Listener) error) {
	path := l.Addr().String()
	klog.V(2).Infof("set up prometheus server on %v", path)
	go func() {
		defer l.Close()
		if err := serveFunc(l); err != nil {
			klog.Fatalf("serve failure(%v), address(%v)", err, path)
		}
	}()
}

func serveMetrics(l net.Listener) error {
	m := http.NewServeMux()
	m.Handle("/metrics", promhttp.Handler())
	return trapClosedConnErr(http.Serve(l, m))
}

func trapClosedConnErr(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
