package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sulakshm/csi-driver/pkg/smb"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

func init() {
	klog.InitFlags(nil)
}

var (
	endpoint                      = flag.String("endpoint", "unix://tmp/csi.sock", "CSI endpoint")
	nodeID                        = flag.String("nodeid", "", "node id")
	driverName                    = flag.String("drivername", smb.DefaultDriverName, "name of the driver")
	ver                           = flag.Bool("ver", false, "Print the version and exit.")
	metricsAddress                = flag.String("metrics-address", "0.0.0.0:29644", "export the metrics")
	kubeconfig                    = flag.String("kubeconfig", "", "Absolute path to the kubeconfig file. Required only when running out of cluster.")
	enableGetVolumeStats          = flag.Bool("enable-get-volume-stats", true, "allow GET_VOLUME_STATS on agent node")
	removeSMBMappingDuringUnmount = flag.Bool("remove-smb-mapping-during-unmount", true, "remove SMBMapping during unmount on Windows node")
	workingMountDir               = flag.String("working-mount-dir", "/tmp", "working directory for provisioner to mount smb shares temporarily")
)

func main() {
	flag.Parse()
	if *ver {
		info, err := smb.GetVersionYAML(*driverName)
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
	exportMetrics()
	handle()
	os.Exit(0)
}

func handle() {
	driverOptions := smb.DriverOptions{
		NodeID:                        *nodeID,
		DriverName:                    *driverName,
		EnableGetVolumeStats:          *enableGetVolumeStats,
		RemoveSMBMappingDuringUnmount: *removeSMBMappingDuringUnmount,
		WorkingMountDir:               *workingMountDir,
	}
	driver := smb.NewDriver(&driverOptions)
	driver.Run(*endpoint, *kubeconfig, false)
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
