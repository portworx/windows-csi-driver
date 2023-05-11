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
	"io/ioutil"
	"os"
	_ "path/filepath"
	_ "runtime"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/sulakshm/csi-driver/pkg/utils"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	_ "k8s.io/kubernetes/pkg/volume"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sulakshm/csi-driver/pkg/mounter"
	"golang.org/x/net/context"
	mount "k8s.io/mount-utils"
)

// / TODO prune and decide the proper context fields to be exchanged
const (
	usernameField        = "username"
	passwordField        = "password"
	sourceField          = "source"
	subDirField          = "subdir"
	domainField          = "domain"
	mountOptionsField    = "mountoptions"
	defaultDomainName    = "AZURE"
	pvcNameKey           = "csi.storage.k8s.io/pvc/name"
	pvcNamespaceKey      = "csi.storage.k8s.io/pvc/namespace"
	pvNameKey            = "csi.storage.k8s.io/pv/name"
	pvcNameMetadata      = "${pvc.metadata.name}"
	pvcNamespaceMetadata = "${pvc.metadata.namespace}"
	pvNameMetadata       = "${pv.metadata.name}"
)

func safeMounter(m mount.Interface) *mount.SafeFormatAndMount {
	p, ok := m.(*mount.SafeFormatAndMount)
	if !ok {
		klog.Fatalf("cannot dereference to needed mount.SafeFormatAndMount")
	}

	return p
}

func nfsMounter(m mount.Interface) mounter.NfsMounter {
	i, ok := m.(mounter.NfsMounter)
	if !ok {
		klog.Fatalf("cannot dereference to needed NfsMounter")
	}
	return i
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

	context := req.GetVolumeContext()
	mountFlags := "rw"
	var source, subDir string
	subDirReplaceMap := map[string]string{}
	/*
		TODO - defined and parse context as necessary later
		mountFlags := req.GetVolumeCapability().GetMount().GetMountFlags()
		volumeMountGroup := req.GetVolumeCapability().GetMount().GetVolumeMountGroup()
		secrets := req.GetSecrets()
		gidPresent := checkGidPresentInMountFlags(mountFlags)

		var source, subDir string
		subDirReplaceMap := map[string]string{}
		for k, v := range context {
			switch strings.ToLower(k) {
			case sourceField:
				source = v
			case subDirField:
				subDir = v
			case pvcNamespaceKey:
				subDirReplaceMap[pvcNamespaceMetadata] = v
			case pvcNameKey:
				subDirReplaceMap[pvcNameMetadata] = v
			case pvNameKey:
				subDirReplaceMap[pvNameMetadata] = v
			}
		}

		if source == "" {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("%s field is missing, current context: %v", sourceField, context))
		}
	*/

	if acquired := d.volumeLocks.TryAcquire(volumeID); !acquired {
		return nil, status.Errorf(codes.Aborted, utils.VolumeOperationAlreadyExistsFmt, volumeID)
	}
	defer d.volumeLocks.Release(volumeID)

	// var username, password, domain string
	/*
		for k, v := range secrets {
			switch strings.ToLower(k) {
			case usernameField:
				username = strings.TrimSpace(v)
			case passwordField:
				password = strings.TrimSpace(v)
			case domainField:
				domain = strings.TrimSpace(v)
			}
		}

		// in guest login, username and password options are not needed
		requireUsernamePwdOption := !hasGuestMountOptions(mountFlags)
	*/

	var mountOptions, sensitiveMountOptions []string
	klog.V(2).Infof("NodeStageVolume: targetPath(%v) volumeID(%v) context(%v) mountflags(%v) mountOptions(%v)",
		targetPath, volumeID, context, mountFlags, mountOptions)

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
		if subDir != "" {
			// replace pv/pvc name namespace metadata in subDir
			subDir = replaceWithMap(subDir, subDirReplaceMap)

			source = strings.TrimRight(source, "/")
			source = fmt.Sprintf("%s/%s", source, subDir)
		}
		mountComplete := false
		err = wait.PollImmediate(1*time.Second, 2*time.Minute, func() (bool, error) {
			err := Mount(safeMounter(d.mounter), source, targetPath, "cifs", mountOptions, sensitiveMountOptions)
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
	if err := CleanupNfsMountPoint(safeMounter(d.mounter), stagingTargetPath, true /*extensiveMountPointCheck*/); err != nil {
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
	proxy := nfsMounter(m.Interface)
	return proxy.NfsMount(source, target, fsType, mountOptions, sensitiveMountOptions)
}

func Unmount(m *mount.SafeFormatAndMount, target string) error {
	proxy := csiMounter(m.Interface)
	return proxy.Unmount(target)
}

func RemoveStageTarget(m *mount.SafeFormatAndMount, target string) error {
	proxy := csiMounter(m.Interface)
	return proxy.Rmdir(target)
}

// CleanupNfsMountPoint - In windows CSI proxy call to umount is used to unmount the SMB.
// The clean up mount point point calls is supposed for fix the corrupted directories as well.
// For alpha CSI proxy integration, we only do an unmount.
func CleanupNfsMountPoint(m *mount.SafeFormatAndMount, target string, extensiveMountCheck bool) error {
	return Unmount(m, target)
}

func CleanupMountPoint(m *mount.SafeFormatAndMount, target string, extensiveMountCheck bool) error {
	if proxy, ok := m.Interface.(mounter.CSIProxyMounter); ok {
		return proxy.Rmdir(target)
	}
	return fmt.Errorf("could not cast to csi proxy class")
}

func removeDir(path string, m *mount.SafeFormatAndMount) error {
	if proxy, ok := m.Interface.(mounter.CSIProxyMounter); ok {
		isExists, err := proxy.ExistsPath(path)
		if err != nil {
			return err
		}

		if isExists {
			klog.V(4).Infof("Removing path: %s", path)
			if err = proxy.Rmdir(path); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("could not cast to csi proxy class")
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
	if proxy, ok := m.Interface.(mounter.CSIProxyMounter); ok {
		return proxy.MakeDir(name)
	}
	return fmt.Errorf("could not cast to csi proxy class")
}

func IsCorruptedDir(dir string) bool {
	_, pathErr := mount.PathExists(dir)
	return pathErr != nil && mount.IsCorruptedMnt(pathErr)
}

// getMountOptions get mountOptions value from a map
func getMountOptions(context map[string]string) string {
	for k, v := range context {
		switch strings.ToLower(k) {
		case mountOptionsField:
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
