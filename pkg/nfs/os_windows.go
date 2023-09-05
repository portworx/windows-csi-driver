//go:build windows
// +build windows

/*
Copyright 2017 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nfs

import (
	"fmt"
	"net"
	"encoding/base64"
	//orgcontext "context"
	"io/ioutil"
	"os"
	//"path"
	_ "path/filepath"
	_ "runtime"
	"strings"
	"math/rand"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/libopenstorage/openstorage/api"
	"github.com/portworx/windows-csi-driver/pkg/utils"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
	_ "k8s.io/kubernetes/pkg/volume"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/portworx/sched-ops/k8s/core"
	"github.com/portworx/windows-csi-driver/pkg/mounter"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	mount "k8s.io/mount-utils"
	k8net "k8s.io/utils/net"

	"github.com/portworx/windows-csi-driver/pkg/common"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/metadata"
)

func safeMounter(m mount.Interface) *mount.SafeFormatAndMount {
	p, ok := m.(*mount.SafeFormatAndMount)
	if !ok {
		klog.Fatalf("cannot dereference to needed mount.SafeFormatAndMount")
	}

	return p
}

func csiMounter(m mount.Interface) mounter.CSIProxyMounter {
	p, ok := m.(*mount.SafeFormatAndMount)
	if !ok {
		klog.Fatalf("cannot dereference to needed mount.SafeFormatAndMount")
	}

	p1, ok := p.Interface.(mounter.CSIProxyMounter)
	if !ok {
		klog.Fatalf("cannot dereference to needed CSIProxyMounter")
	}
	return p1
}

// NodePublishVolume: Mount the volume to the target location.

func (d *nfsDriver) nfsNodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	klog.V(2).Infof("NodePublishVolume")

	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability missing in request")
	}
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}

	target := req.GetTargetPath()
	if len(target) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path not provided")
	}

	if acquired := d.volumeLocks.TryAcquire(volumeID); !acquired {
		return nil, status.Errorf(codes.Aborted, utils.VolumeOperationAlreadyExistsFmt, volumeID)
	}
	defer d.volumeLocks.Release(volumeID)

	mountOptions := []string{"bind"}
	if req.GetReadonly() {
		mountOptions = append(mountOptions, "ro")
	}

	mnt, err := d.ensureMountPoint(target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not mount target %q: %v", target, err)
	}
	if mnt {
		klog.V(2).Infof("NodePublishVolume: %s is already mounted", target)
		return &csi.NodePublishVolumeResponse{}, nil
	}

	ipAddr, err := d.getRpcAddr()
	if err != nil {
		return nil, err
	}
	endpoint, err := d.getEndpoint(ctx, volumeID, ipAddr, target)
	if err != nil {
		klog.V(2).Infof("NodePublishVolume: IpAddress [%v] volumeID[%v] Unable to open Grpc connection. Error[%v]", ipAddr, volumeID, err)
		return nil, err
	}
	exportpath := fmt.Sprintf("/var/lib/osd/pxns/%s", volumeID)
	source := fmt.Sprintf("\\\\%s\\%s", endpoint, exportpath)

	if err = preparePublishPath(target, safeMounter(d.mounter)); err != nil {
		return nil, fmt.Errorf("prepare publish failed for %s with error: %v", target, err)
	}

	klog.V(2).Infof("NodePublishVolume: mounting %s at %s with mountOptions: %v volumeID(%s)", source, target, mountOptions, volumeID)
	m := csiMounter(d.mounter)
	if err := m.NfsMount(source, target, "nfs", mountOptions, nil); err != nil {
		klog.V(2).Infof("NodePublishVolume: mounting %s at %s with mountOptions: %v volumeID(%s) Failed with error [%v]", source, target, mountOptions, volumeID, err)
		if removeErr := os.Remove(target); removeErr != nil {
			return nil, status.Errorf(codes.Internal, "Could not remove mount target %q: %v", target, removeErr)
		}
		return nil, status.Errorf(codes.Internal, "Could not mount %q at %q: %v", source, target, err)
	}
	klog.V(2).Infof("NodePublishVolume: mount %s at %s volumeID(%s) successfully", source, target, volumeID)
	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume unmount the volume from the target path
func (d *nfsDriver) nfsNodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	targetPath := req.GetTargetPath()
	if len(targetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path missing in request")
	}

	klog.V(2).Infof("NodeUnpublishVolume: unmounting volume %s on %s", volumeID, targetPath)
	if acquired := d.volumeLocks.TryAcquire(volumeID); !acquired {
		klog.V(2).Infof("NodeUnpublishVolume: Acquiring lock on volumeID[%s] faliled, another operation in progress", volumeID)
		return nil, status.Errorf(codes.Aborted, utils.VolumeOperationAlreadyExistsFmt, volumeID)
	}
	defer d.volumeLocks.Release(volumeID)

	err := CleanupMountPoint(safeMounter(d.mounter), targetPath, true /*extensiveMountPointCheck*/)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmount target %q: %v", targetPath, err)
	}
	klog.V(2).Infof("NodeUnpublishVolume: CleanupMountPoint for %s %s successful", volumeID, targetPath)

	m := csiMounter(d.mounter)
	if err := m.NfsUnmount(volumeID, targetPath); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmount targetPath %q: %v", targetPath, err)
	}

	// Inform Linux Px nodes.
	klog.V(2).Infof("NodeUnpublishVolume: NfsUnmount successful for %s %s. Informing Px", volumeID, targetPath)
	ipAddr, err := d.getRpcAddr()
	if err != nil {
		return nil, err
	}
	myip, err := getLocalIPList()
	driverOpts := make(map[string]string)
	driverOpts["WindowsClient"] = "true"
	if myip != "" {
		driverOpts[api.OptProxyCaller] = myip
		driverOpts[api.OptProxyCallerIP] = myip
		driverOpts[api.OptMountID] = base64.StdEncoding.EncodeToString(
                        []byte(strings.TrimSuffix(targetPath, "/")),
			)
	}
	conn, err := grpc.Dial(ipAddr, grpc.WithInsecure())
	if err != nil {
		klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v] Unable to open Grpc connection. Error[%v]", ipAddr, volumeID, err)
		return nil, err
	}
	volumeClient := api.NewOpenStorageVolumeClient(conn)
	volInfo, err := volumeClient.Inspect(ctx, &api.SdkVolumeInspectRequest{VolumeId: volumeID})
	if err != nil {
		klog.V(2).Infof("getEndpoint: IpAddress [%v] volumeID[%v] Inspect failed. Error[%v]", ipAddr, volumeID, err)
		conn.Close()
		return nil, err
	}
	splitStrings := strings.Split(ipAddr, ":")
	gRpcPort := splitStrings[1]
	clientIP := volInfo.GetVolume().GetAttachedOn()
	if clientIP != "" {
		ipAddr = fmt.Sprintf("%s:%s", clientIP, gRpcPort)
		newconn, err := grpc.Dial(ipAddr, grpc.WithInsecure())
		if err != nil {
			klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v] Unable to open Grpc connection to Attached Node. Error[%v]", ipAddr, volumeID, err)
			return nil, err
		}
		conn.Close()
		conn = newconn
	}
	defer conn.Close()

	//mountPath := path.Join(api.SharedVolExportPrefix, volumeID)
	mountPath := fmt.Sprintf("/var/lib/osd/pxns/%s", volumeID)
	mountUnmountClient := api.NewOpenStorageMountAttachClient(conn)
	klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v]: Issuing Unmount path[%s]", ipAddr, volumeID, err, mountPath)
	_, err = mountUnmountClient.Unmount(ctx, &api.SdkVolumeUnmountRequest{MountPath: mountPath, VolumeId: volumeID,  DriverOptions: driverOpts})
	if  err != nil {
		klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v] Unable to Unmount volume. Error[%v]", ipAddr, volumeID, err)
		return nil, err
	}
	klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v]: Issuing Detach path[%s]", ipAddr, volumeID, err, mountPath)
	_, err = mountUnmountClient.Detach(ctx, &api.SdkVolumeDetachRequest{VolumeId: volumeID,  DriverOptions: driverOpts})
	if  err != nil {
		klog.V(2).Infof("NodeUnpublishVolume: IpAddress [%v] volumeID[%v] Unable to Detach volume. Error[%v]", ipAddr, volumeID, err)
		return nil, err
	}
	klog.V(2).Infof("NodeUnpublishVolume: Returning success{}")

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// getLocalIPList returns the list of local IP addresses, and optionally includes local hostname.
func getLocalIPList() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			//                logrus.WithError(err).Warnf("Error listing address for %s (cont.)", i.Name)
			klog.V(2).Infof("Error listing address for %s (cont.)", i.Name)
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// process IP address
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && k8net.IsIPv4(ip) {
				klog.V(2).Infof("MyIP=%s", ip.String())
				return ip.String(), nil
			}
		}
	}
	return "", status.Error(codes.InvalidArgument, "failed to get localip")
}

func (d* nfsDriver)getPxPort() (string, error) {
	// TODO: Remove the hardcode and search for portworx-service in all namespaces.
	svc, err := core.Instance().GetService("portworx-service", "kube-system")
	if err != nil {
		klog.V(2).Infof("Failed to get Portworx Service, error[%v]", err)
		return "", err
	}

	var gRpcPort string
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
	return gRpcPort, nil
}

func (d *nfsDriver)getRpcAddr() (string, error) {
	// Get Rpc port from portworx service.

	// Get the node IP. Pick one randomly
	// TODO: Check node is Ready.
	// Pick a linux node. For now pick the first node.
	gRpcPort, err := d.getPxPort()
	if err != nil {
		return "", err
	}
	var ipfound bool
	var ip string
	var ips = make(map[int]string)
	var i = 0
	nodes, errnodes := core.Instance().GetNodes()
	if errnodes != nil {
		klog.V(2).Infof("Getting Node information failed error[%v]", errnodes)
		return "", err
	}
	// For each node, get's it's annotations and labels
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
			csi, ok := nodeLabels["csi.volume.kubernetes.io/nodeid"]
			if ok && strings.Contains(csi, "pxd.portworx.com") {
				skipNode := false
				for _, condition := range n.Status.Conditions {
					if condition.Type == "Ready" {
						if condition.Status != "True" {
							skipNode  = true
						}
					}
				}

				if !skipNode {
					for _, addr := range n.Status.Addresses {
						switch addr.Type {
						case corev1.NodeInternalIP:
							ip = addr.Address
							ipfound = true
							ips[i] = ip
							i = i+1
							break
						}
					}
				}
			}
		}
	}
	if !ipfound {
		return "", status.Error(codes.NotFound, "No suitable linux node found")
	}

	randNum := rand.Intn(i)
	str := fmt.Sprintf("%s:%s", ips[randNum], gRpcPort)
	return str, nil
}

func (d *nfsDriver) getEndpoint(ctx context.Context, volumeID string, ipAddr, targetPath string) (string, error) {
	myip, err := getLocalIPList()
	driverOpts := make(map[string]string)
	driverOpts["WindowsClient"] = "true"
	if myip != "" {
		driverOpts[api.OptProxyCaller] = myip
		driverOpts[api.OptProxyCallerIP] = myip
		driverOpts[api.OptMountID] = base64.StdEncoding.EncodeToString(
                        []byte(strings.TrimSuffix(targetPath, "/")),
			)
	}
	conn, err := grpc.Dial(ipAddr, grpc.WithInsecure())
	if err != nil {
		klog.V(2).Infof("getEndpoint: IpAddress [%v] volumeID[%v] Unable to open Grpc connection. Error[%v]", ipAddr, volumeID, err)
		return "", err
	}
	defer conn.Close()

	mountUnmountClient := api.NewOpenStorageMountAttachClient(conn)
	_, err = mountUnmountClient.Attach(ctx, &api.SdkVolumeAttachRequest{VolumeId: volumeID})
	if err != nil {
		klog.V(2).Infof("getEndpoint: IpAddress [%v] volumeID[%v] Attach failed. Error[%v]", ipAddr, volumeID, err)
		return "", err
	}
	//mountPath := path.Join(api.SharedVolExportPrefix, volumeID)
	mountPath := fmt.Sprintf("/var/lib/osd/pxns/%s", volumeID)
	_, err = mountUnmountClient.Mount(ctx, &api.SdkVolumeMountRequest{MountPath: mountPath, VolumeId: volumeID, DriverOptions: driverOpts})
	if err != nil {
		klog.V(2).Infof("getEndpoint: IpAddress [%v] volumeID[%v] Mount failed. Error[%v]", ipAddr, volumeID, err)
		return "", err
	}
	volumeClient := api.NewOpenStorageVolumeClient(conn)
	volInfo, err := volumeClient.Inspect(ctx, &api.SdkVolumeInspectRequest{VolumeId: volumeID})
	if err != nil {
		klog.V(2).Infof("getEndpoint: IpAddress [%v] volumeID[%v] Inspect failed. Error[%v]", ipAddr, volumeID, err)
		return "", err
	}
	return volInfo.GetVolume().GetAttachedOn(), nil
}

// ensureMountPoint: create mount point if not exists
// return <true, nil> if it's already a mounted point otherwise return <false, nil>
func (d *nfsDriver) ensureMountPoint(target string) (bool, error) {
	notMnt, err := d.mounter.IsLikelyNotMountPoint(target)
	if err != nil && !os.IsNotExist(err) {
		if IsCorruptedDir(target) {
			notMnt = false
			klog.Warningf("detected corrupted mount for targetPath [%s]", target)
		} else {
			return !notMnt, err
		}
	}

	if !notMnt {
		// testing original mount point, make sure the mount link is valid
		_, err := ioutil.ReadDir(target)
		if err == nil {
			klog.V(2).Infof("already mounted to target %s", target)
			return !notMnt, nil
		}
		// mount link is invalid, now unmount and remount later
		klog.Warningf("ReadDir %s failed with %v, unmount this directory", target, err)
		if err := d.mounter.Unmount(target); err != nil {
			klog.Errorf("Unmount directory %s failed with %v", target, err)
			return !notMnt, err
		}
		notMnt = true
		return !notMnt, err
	}

	if err := makeDir(target); err != nil {
		klog.Errorf("MakeDir failed on target: %s (%v)", target, err)
		return !notMnt, err
	}

	return false, nil
}

func makeDir(pathname string) error {
	err := os.MkdirAll(pathname, os.FileMode(0755))
	if err != nil {
		if !os.IsExist(err) {
			return err
		}
	}
	return nil
}

func Mount(m *mount.SafeFormatAndMount, source, target, fsType string, mountOptions, sensitiveMountOptions []string) error {
	proxy := csiMounter(m.Interface)
	return proxy.NfsMount(source, target, fsType, mountOptions, sensitiveMountOptions)
}

func CleanupMountPoint(m *mount.SafeFormatAndMount, target string, extensiveMountCheck bool) error {
	if err := os.Remove(target); err != nil {
		klog.V(2).Infof("Removing path: %s, failed %v", target, err)
	}
	return nil
}

func removeDir(path string, m *mount.SafeFormatAndMount) error {
	klog.V(4).Infof("Removing path: %s", path)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// preparePublishPath - In case of windows, the publish code path creates a soft link
// from global stage path to the publish path. But kubelet creates the directory in advance.
// We work around this issue by deleting the publish path then recreating the link.
func preparePublishPath(path string, m *mount.SafeFormatAndMount) error {
	return removeDir(path, m)
}

func Mkdir(m *mount.SafeFormatAndMount, name string, perm os.FileMode) error {
	return os.MkdirAll(name, 0750)
}

func IsCorruptedDir(dir string) bool {
	_, pathErr := mount.PathExists(dir)
	return pathErr != nil && mount.IsCorruptedMnt(pathErr)
}

// getMountOptions get mountOptions value from a map
func getMountOptions(context map[string]string) string {
	for k, v := range context {
		switch strings.ToLower(k) {
		case common.MountOptionsField:
			return v
		}
	}
	return ""
}

func hasGuestMountOptions(options []string) bool {
	for _, v := range options {
		if v == "guest" {
			return true
		}
	}
	return false
}

// setKeyValueInMap set key/value pair in map
// key in the map is case insensitive, if key already exists, overwrite existing value
func setKeyValueInMap(m map[string]string, key, value string) {
	if m == nil {
		return
	}
	for k := range m {
		if strings.EqualFold(k, key) {
			m[k] = value
			return
		}
	}
	m[key] = value
}

// replaceWithMap replace key with value for str
func replaceWithMap(str string, m map[string]string) string {
	for k, v := range m {
		if k != "" {
			str = strings.ReplaceAll(str, k, v)
		}
	}
	return str
}

func newContext() context.Context {
	return setContextWithToken(context.Background())
}

func setContextWithToken(ctx context.Context) context.Context {
	//if contextconfig.CurrentContext == nil {
	return ctx
	//}
	//md := metadata.New(map[string]string{
	//"authorization": "bearer " + contextconfig.CurrentContext.Token,
	//})
	//return metadata.NewOutgoingContext(ctx, md)
}
