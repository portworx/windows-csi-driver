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
	//orgcontext "context"
	"io/ioutil"
	"os"
	_ "path/filepath"
	_ "runtime"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/libopenstorage/openstorage/api"
	"github.com/portworx/windows-csi-driver/pkg/utils"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	_ "k8s.io/kubernetes/pkg/volume"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/portworx/sched-ops/k8s/core"
	"github.com/portworx/windows-csi-driver/pkg/mounter"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	mount "k8s.io/mount-utils"

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

// NodePublishVolume mount the volume from staging to target path
func (d *nfsDriver) nfsNodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
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

	source := req.GetStagingTargetPath()
	if len(source) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

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

	if err = preparePublishPath(target, safeMounter(d.mounter)); err != nil {
		return nil, fmt.Errorf("prepare publish failed for %s with error: %v", target, err)
	}

	klog.V(2).Infof("NodePublishVolume: mounting %s at %s with mountOptions: %v volumeID(%s)", source, target, mountOptions, volumeID)
	if err := d.mounter.Mount(source, target, "", mountOptions); err != nil {
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
	err := CleanupMountPoint(safeMounter(d.mounter), targetPath, true /*extensiveMountPointCheck*/)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmount target %q: %v", targetPath, err)
	}
	klog.V(2).Infof("NodeUnpublishVolume: unmount volume %s on %s successfully", volumeID, targetPath)
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
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				klog.V(2).Infof("MyIP=%s", ip.String())
				return ip.String(), nil
			}
		}
	}
	return "", status.Error(codes.InvalidArgument, "failed to get localip")
}

// NodeStageVolume mount the volume to a staging path
func (d *nfsDriver) nfsNodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}

	volumeCapability := req.GetVolumeCapability()
	if volumeCapability == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability not provided")
	}

	targetPath := req.GetStagingTargetPath()
	if len(targetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}
	myip, err := getLocalIPList()
	var (
		exportpath            string
		source                string
		ip                    string
		mountOptions          []string
		sensitiveMountOptions []string
		ipfound               bool
		endpoint              string
		csimode               string
	)

	svc, err := core.Instance().GetService("portworx-service", "kube-system")
	if err != nil {
		klog.V(2).Infof("Failed to get Portworx Service, error[%v]", err)
		return nil, err
	}

	var restPort, gRpcPort string
	for _, svcPort := range svc.Spec.Ports {
		if svcPort.Name == "px-sdk" {
			targetPort := svcPort.TargetPort
			if targetPort.Type == intstr.String {
				gRpcPort = targetPort.StrVal
			} else {
				gRpcPort = fmt.Sprintf("%d", targetPort.IntValue())
			}
		} else if svcPort.Name == "px-rest" {
			targetPort := svcPort.TargetPort
			if targetPort.Type == intstr.String {
				restPort = targetPort.StrVal
			} else {
				restPort = fmt.Sprintf("%d", targetPort.IntValue())
			}
		}
	}

	// Pick a linux node. For now pick the first node.
	nodes, errnodes := core.Instance().GetNodes()
	if errnodes != nil {
		klog.V(2).Infof("Phani: Getting Node information failed error[%v]", errnodes)
	} else {
		// For each node, get's it's annotations and labels
		for _, n := range nodes.Items {
			nodeLabels := make(map[string]string)
			for k, v := range n.GetLabels() {
				nodeLabels[k] = v
			}

			for k, v := range n.GetAnnotations() {
				nodeLabels[k] = v
			}
			klog.V(2).Infof("NodePublishVolume: Kubenetest Node [%v] Labels[%v]", n.GetName(), nodeLabels)
			v, ok := nodeLabels["beta.kubernetes.io/os"]
			if ok && v == "linux" {
				csi, ok := nodeLabels["csi.volume.kubernetes.io/nodeid"]
				if ok && strings.Contains(csi, "pxd.portworx.com") {
					if !ipfound {
						for _, addr := range n.Status.Addresses {
							switch addr.Type {
							case corev1.NodeInternalIP:
								ip = addr.Address
								ipfound = true
								break
							}
						}
					}
				}
			}
		}
	}

	// For Windows share volume:
	// On the linux node : Attach + Mount.
	// Inspect the volume.
	// handcraft export path /var/lib/osd/pxns/<volumeID>
	// mount \\<attachedon>\exportpath.

	useGrpc := true
	if ipfound {
		driverOpts := make(map[string]string)
		driverOpts["WindowsClient"] = "true"
		if myip != "" {
			driverOpts["CallingNodeIP"] = myip
		}
		if useGrpc {
			host := fmt.Sprintf("%s:%s", ip, gRpcPort)
			klog.V(2).Infof("NodeStageVolume: host[%v]", host)
			conn, err := grpc.Dial(host, grpc.WithInsecure())
			if err != nil {
				klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v] Unable to open Grpc connection. Error[%v]", ip, volumeID, err)
				return nil, err
			}

			mountUnmountClient := api.NewOpenStorageMountAttachClient(conn)
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]: Issuing Attach Grpc", ip, volumeID)
			_, err = mountUnmountClient.Attach(ctx, &api.SdkVolumeAttachRequest{VolumeId: volumeID})
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]: Attach returned [%v]", ip, volumeID, err)
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]: Issuing Mount Grpc", ip, volumeID)
			_, err = mountUnmountClient.Mount(ctx, &api.SdkVolumeMountRequest{MountPath: "/dummy", VolumeId: volumeID, DriverOptions: driverOpts})
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]: Mount returned [%v]", ip, volumeID, err)
			volumeClient := api.NewOpenStorageVolumeClient(conn)
			volInfo, err := volumeClient.Inspect(ctx, &api.SdkVolumeInspectRequest{VolumeId: volumeID})
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]: Inspect returned [%v] volInfo[%v]", ip, volumeID, err, volInfo)
			endpoint = volInfo.GetVolume().GetAttachedOn()
			exportpath = fmt.Sprintf("/var/lib/osd/pxns/%s", volumeID)
		} else {
			klog.V(2).Infof("NodeStageVolume: IpAddress [%v] volumeID[%v]", ip, volumeID)
			cmdLine := fmt.Sprintf(
				`Invoke-RestMethod -Uri "http://%s:%s/v1/mountattach/attach " `+
					`-Method Post -ContentType "application/json" -Body "{`+"`"+
					`"volume_id`+"`"+`":`+"`"+`"%s`+"`"+`"}"`, ip, restPort, volumeID)
			out1, out2, err := mounter.RunPowershellCmd(cmdLine)
			outString := string(out2[:])
			outString2 := string(out1[:])
			klog.V(2).Infof("NodeStageVolume: Attach CLI[%v] Error[%v] Out1[%v] Out2[%v]", cmdLine, err, outString2, outString)
			cmdLine = fmt.Sprintf(
				`Invoke-RestMethod -Uri "http://%s:%s/v1/mountattach/mount "`+
					`-Method Post -ContentType "application/json" -Body "{`+
					"`"+`"mount_path`+"`"+`":`+"`"+`"/dummy`+"`"+`", `+"`"+`"volume_id`+"`"+`":`+
					"`"+`"%s`+"`"+`"}"`, ip, restPort, volumeID)
			out1, out2, err = mounter.RunPowershellCmd(cmdLine)
			outString = string(out2[:])
			outString2 = string(out1[:])
			klog.V(2).Infof("NodeStageVolume: Mount CLI[%v] Error[%v] Out1[%v] Out2[%v]", cmdLine, err, outString2, outString)
			cmdLine = fmt.Sprintf(
				`$res = Invoke-RestMethod -Uri "http://%s:%s/v1/volumes/inspect/%s"; echo $res.volume.attached_on`, ip, restPort, volumeID)
			out1, out2, err = mounter.RunPowershellCmd(cmdLine, fmt.Sprintf("ip_address=%s", ip), fmt.Sprintf("volume_id=%s", volumeID))
			outString = string(out2[:])
			outString2 = string(out1[:])
			outString2 = strings.TrimSuffix(outString2, "\r\n")
			klog.V(2).Infof("NodeStageVolume: Inspect CLI[%v], volumeInfo[%v] Error[%v] out1[%v]", cmdLine, outString2, err, outString)
			endpoint = outString2
			exportpath = fmt.Sprintf("/var/lib/osd/pxns/%s", volumeID)
		}
	} else {
		context := req.GetPublishContext()
		_, ok := context[common.CsimodeField]
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "csimode not specified in context")
		}
		endpoint, ok = context[common.EndpointField]
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "nfs endpoint not specified in context")
		}
		exportpath, ok = context[common.ExportpathField]
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "nfs export path not specified in context")
		}
	}

	csimode = "nfs"

	source = fmt.Sprintf("\\\\%s\\%s", endpoint, exportpath)

	// THis path needs to be normalized, that happens within mounter package

	klog.V(2).Infof("NodeStageVolume: volume %s, endpoint(%v), share(%v) - full source %s",
		volumeID, endpoint, exportpath, source)

	if acquired := d.volumeLocks.TryAcquire(volumeID); !acquired {
		return nil, status.Errorf(codes.Aborted, utils.VolumeOperationAlreadyExistsFmt, volumeID)
	}
	defer d.volumeLocks.Release(volumeID)

	isDirMounted, err := d.ensureMountPoint(targetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not mount target %s: %v", targetPath, err)
	}
	if isDirMounted {
		klog.V(2).Infof("NodeStageVolume: already mounted volume %s on target %s", volumeID, targetPath)
	} else {
		if err = prepareStagePath(targetPath, safeMounter(d.mounter)); err != nil {
			return nil, fmt.Errorf("prepare stage path failed for %s with error: %v", targetPath, err)
		}
		mountComplete := false
		err = wait.PollImmediate(1*time.Second, 2*time.Minute, func() (bool, error) {
			m := csiMounter(d.mounter)
			if csimode == "nfs" {
				err = m.NfsMount(source, targetPath, "nfs", mountOptions, sensitiveMountOptions)
			} else {
				err = m.SMBMount(source, targetPath, "cifs", mountOptions, sensitiveMountOptions)
			}
			//err := Mount(safeMounter(d.mounter), source, targetPath, "nfs", mountOptions, sensitiveMountOptions)
			mountComplete = true
			return true, err
		})
		if !mountComplete {
			return nil, status.Error(codes.Internal, fmt.Sprintf("volume(%s) mount %q on %q failed with timeout(10m)", volumeID, source, targetPath))
		}
		if err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("volume(%s) mount %q on %q failed with %v", volumeID, source, targetPath, err))
		}
		klog.V(2).Infof("volume(%s) mount %q on %q succeeded", volumeID, source, targetPath)
	}

	return &csi.NodeStageVolumeResponse{}, nil
}

// NodeUnstageVolume unmount the volume from the staging path
func (d *nfsDriver) nfsNodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	stagingTargetPath := req.GetStagingTargetPath()
	if len(stagingTargetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

	if acquired := d.volumeLocks.TryAcquire(volumeID); !acquired {
		return nil, status.Errorf(codes.Aborted, utils.VolumeOperationAlreadyExistsFmt, volumeID)
	}
	defer d.volumeLocks.Release(volumeID)

	klog.V(2).Infof("NodeUnstageVolume: CleanupMountPoint on %s with volume %s", stagingTargetPath, volumeID)
	m := csiMounter(d.mounter)
	if err := m.NfsUnmount(volumeID, stagingTargetPath); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmount staging target %q: %v", stagingTargetPath, err)
	}
	klog.V(2).Infof("NodeUnstageVolume: unmount volume %s on %s successfully", volumeID, stagingTargetPath)
	return &csi.NodeUnstageVolumeResponse{}, nil
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

func checkGidPresentInMountFlags(mountFlags []string) bool {
	for _, mountFlag := range mountFlags {
		if strings.HasPrefix(mountFlag, "gid") {
			return true
		}
	}
	return false
}

func Mount(m *mount.SafeFormatAndMount, source, target, fsType string, mountOptions, sensitiveMountOptions []string) error {
	proxy := csiMounter(m.Interface)
	return proxy.NfsMount(source, target, fsType, mountOptions, sensitiveMountOptions)
}

func RemoveStageTarget(m *mount.SafeFormatAndMount, target string) error {
	if err := os.Remove(target); err != nil {
		klog.V(2).Infof("Removing path: %s, failed %v", target, err)
	}
	return nil
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

func prepareStagePath(path string, m *mount.SafeFormatAndMount) error {
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
