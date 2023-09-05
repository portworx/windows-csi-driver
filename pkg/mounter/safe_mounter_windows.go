//go:build windows
// +build windows

/*
Copyright 2020 The Kubernetes Authors.

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

package mounter

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	filepath "path/filepath"
	"strings"

	"github.com/portworx/windows-csi-driver/pkg/common"
	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"
)

// CSIProxyMounter extends the mount.Interface interface with CSI Proxy methods.
type CSIProxyMounter interface {
	mount.Interface

	NfsMounter

	MakeDir(path string) error
	Rmdir(path string) error
	IsMountPointMatch(mp mount.MountPoint, dir string) bool
	ExistsPath(path string) (bool, error)
	EvalHostSymlinks(pathname string) (string, error)
}

var _ CSIProxyMounter = &csiProxyMounter{}

type csiProxyMounter struct {
	Mode                          common.DriverModeFlag
	RemoveSMBMappingDuringUnmount bool
}

func normalizeWindowsPath(path string, networkpath bool) string {
	normalizedPath := strings.Replace(path, "/", "\\", -1)
	if strings.HasPrefix(normalizedPath, "\\") && !networkpath {
		normalizedPath = "c:" + normalizedPath
	}
	return normalizedPath
}

func (mounter *csiProxyMounter) Mount(source string, target string, fstype string, options []string) error {
	klog.V(2).Infof("Mount Called for Source[%s] Target[%s] FsType[%s]", source, target, fstype)
	return nil
}

// Unmount - Removes the directory - equivalent to unmount on Linux.
func (mounter *csiProxyMounter) Unmount(target string) error {
	klog.V(2).Infof("Unmount called for Target [%s]", target)
	return mounter.Rmdir(target)
}

func Split(r rune) bool {
	return r == ' ' || r == '/' || r == '\\'
}

// Rmdir - delete the given directory
// TODO: Call separate rmdir for pod context and plugin context. v1alpha1 for CSI
//
//	proxy does a relaxed check for prefix as c:\var\lib\kubelet, so we can do
//	rmdir with either pod or plugin context.
func (mounter *csiProxyMounter) Rmdir(path string) error {
	klog.V(4).Infof("Remove directory: %s", path)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (mounter *csiProxyMounter) List() ([]mount.MountPoint, error) {
	return []mount.MountPoint{}, fmt.Errorf("List not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) IsMountPointMatch(mp mount.MountPoint, dir string) bool {
	return mp.Path == dir
}

// IsLikelyMountPoint - If the directory does not exists, the function will return os.ErrNotExist error.
//
//	If the path exists, call to CSI proxy will check if its a link, if its a link then existence of target
//	path is checked.
func (mounter *csiProxyMounter) IsLikelyNotMountPoint(path string) (bool, error) {
	klog.V(4).Infof("IsLikelyNotMountPoint: %s", path)
	info, err := os.Stat(normalizeWindowsPath(path, false))
	if err == nil {
		return os.ModeSymlink&info.Mode() != os.ModeSymlink, nil
	}
	if os.IsNotExist(err) {
		return true, os.ErrNotExist
	}
	klog.V(4).Infof("IsLikelyNotMountPoint: Stat on path %s returned %v", path, err)
	return false, err
}

func (mounter *csiProxyMounter) PathIsDevice(pathname string) (bool, error) {
	return false, fmt.Errorf("PathIsDevice not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) DeviceOpened(pathname string) (bool, error) {
	return false, fmt.Errorf("DeviceOpened not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetDeviceNameFromMount(mountPath, pluginMountDir string) (string, error) {
	return "", fmt.Errorf("GetDeviceNameFromMount not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MakeRShared(path string) error {
	return fmt.Errorf("MakeRShared not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MakeFile(pathname string) error {
	return fmt.Errorf("MakeFile not implemented for CSIProxyMounter")
}

// MakeDir - Creates a directory. The CSI proxy takes in context information.
// Currently the make dir is only used from the staging code path, hence we call it
// with Plugin context..
func (mounter *csiProxyMounter) MakeDir(path string) error {
	klog.V(4).Infof("Make directory: %s", path)
	return os.MkdirAll(path, 0750)
}

// ExistsPath - Checks if a path exists. Unlike util ExistsPath, this call does not perform follow link.
func (mounter *csiProxyMounter) ExistsPath(path string) (bool, error) {
	klog.V(4).Infof("Exists path: %s", path)
	_, err := os.Stat(normalizeWindowsPath(path, false))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (mounter *csiProxyMounter) EvalHostSymlinks(pathname string) (string, error) {
	return filepath.EvalSymlinks(pathname)
}

func (mounter *csiProxyMounter) GetMountRefs(pathname string) ([]string, error) {
	return []string{}, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetSELinuxSupport(pathname string) (bool, error) {
	return false, fmt.Errorf("GetSELinuxSupport not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetMode(pathname string) (os.FileMode, error) {
	return 0, fmt.Errorf("GetMode not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return fmt.Errorf("MountSensitive not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitiveWithoutSystemd(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemd not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitiveWithoutSystemdWithMountFlags(source string, target string, fstype string, options []string, sensitiveOptions []string, mountFlags []string) error {
	return mounter.MountSensitive(source, target, fstype, options, sensitiveOptions /* sensitiveOptions */)
}

// NFS Extensions

// TargetPath: <podID + volumeID>
// SharePath: \\NFSServer\<exportPath>
// Nfs mount with Name TargetPath SharePath.
// SoftLink => C:\var\pwxvol\TargetPath SharePath.
// SoftLink => PublishPath to C:\var\pwxvol\TargetPath

func (mounter *csiProxyMounter) AddDrive(
	volid string,
	share_path string,
	sensitiveMountOptions []string,
	targetPath string,
) error {

	klog.V(2).Infof("AddDrive: volid %s, source %s, targetPath %s, sensitiveOpts %v",
		volid, share_path, targetPath, sensitiveMountOptions)

	cmdLine := fmt.Sprintf(`New-PSDrive -Name ${Env:volid} -PSProvider FileSystem ` +
		`-Root ${Env:path} -Scope Global -Description ${Env:pwxtag}`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("volid=%s", targetPath),
		fmt.Sprintf("path=%s", share_path),
		fmt.Sprintf("pwxtag=%s", pwxtag))

	if err != nil {
		klog.V(2).Infof("AddDrive: volid %s, cmd %v, failed %v", volid, cmdLine, err)
		return fmt.Errorf("error nfs mounting. cmd %s, output %s. err %v", cmdLine, string(out), err)
	}

	klog.V(2).Infof("Successfully mounted Path from  %s, to ", share_path)
	workPath := volumePath(targetPath)
	_, err = os.Stat(workPath)
	if err == nil {
		os.Remove(workPath)
	}

	klog.V(2).Infof("AddDrive: Creating Path from  %s, to %s", workPath, share_path)
	cmdLine = fmt.Sprintf("mklink /D %s %s", workPath, share_path)
	_, out, err = RunCmd(cmdLine)
	if err != nil {
		klog.V(2).Infof("AddDrive MkVolume: volid %s, failed %v", volid, err)
		return fmt.Errorf("error mkvolume. cmd %s, output %s, err %v", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) RmDrive(
	volid, targetPath string,
) error {
	klog.V(2).Infof("RmDrive: volid %s targetPath %s", volid, targetPath)
	cmdLine := fmt.Sprintf(`Remove-PSDrive -Name ${Env:volid}`)
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("volid=%s", targetPath))
	if err != nil {
		klog.V(2).Infof("RmDrive: volid %s, cmd %v, failed %s/%v", volid, cmdLine, string(out), err)
	}
	return nil
}

func (mounter *csiProxyMounter) DriveInfo(
	volid string,
) (*DriveInfoObj, bool, error) {
	klog.V(2).Infof("DriveInfo: volid %s", volid)

	// Lookup will always fail as the New-PSDrive creates a temporary drive for the session.
	// Will not be available for global lookup

	// runs:
	// ConvertTo-Json -InputObject @(Get-PSDrive -Name Public -ErrorAction Ignore)
	cmdLine := fmt.Sprintf(`ConvertTo-Json -InputObject @(Get-PSDrive -Name ${Env:volid} -ErrorAction Ignore)`)
	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("volid=%s", volid))
	if err != nil {
		klog.V(2).Infof("DriveInfo: volid %s, cmd %v, failed %v", volid, cmdLine, err)
		return nil, false, fmt.Errorf("error driveinfo. cmd %s, output %s, err %v", cmdLine, string(stderr), err)
	}

	var d []DriveInfoObj
	err = json.Unmarshal(out, &d)
	if err != nil {
		klog.V(2).Infof("DriveInfo: volid %s, parse failed %v", volid, err)
		return nil, false, fmt.Errorf("error parsing driveinfo. out %v, err %v", out, err)
	}

	if len(d) == 0 {
		return nil, false, nil
	}

	for _, drv := range d {
		if drv.Name == volid && drv.Description == pwxtag {
			return &drv, true, nil
		}
	}

	return nil, false, nil
}

func (mounter *csiProxyMounter) DriveExists(
	volid string,
) (bool, error) {
	klog.V(2).Infof("DriveExists: volid %s", volid)

	_, ok, err := mounter.DriveInfo(volid)

	return ok, err
}

func (mounter *csiProxyMounter) MkLink(volid, target string) error {
	// runs:
	// New-item -Path c:\myvol\vol1 -ItemType SymbolicLink -Value c:\pwxvol\615688357680565115
	klog.V(2).Infof("MkLink: volid %s, target %s", volid, target)

	// internal work dir path for mounted volume
	workPath := volumePath(volid)

	cmdLine := fmt.Sprintf("New-Item -Path ${Env:target} -ItemType SymbolicLink -Value ${Env:workPath}")
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("workPath=%s", workPath), fmt.Sprintf("target=%s", target))
	if err != nil {
		klog.V(2).Infof("MkLink: volid %s, target %s, failed %v", volid, target, err)
		return fmt.Errorf("error mkvolume. cmd %s, output %s, err %v", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) RmLink(volid, target string) error {
	// runs:
	// Remove-item does not properly remove symlinks, use os.Remove and see if it work
	klog.V(2).Infof("RmLink: volid %s, target %s", volid, target)

	path := volumePath(volid)
	err := os.Remove(path)
	if err != os.ErrNotExist {
		klog.V(2).Infof("RmLink: volid %s, target %s, failed %v", volid, target, err)
		return err
	}

	return nil
}

func (mounter *csiProxyMounter) getMountTargetID(target, volid string) (string, error) {
	targetParts := strings.FieldsFunc(target, Split)
	klog.V(2).Infof("norm target %v, split %+v", target, targetParts)
	var podID string
	var i int
	for i = 0; i < len(targetParts) - 1; i++ {
		if targetParts[i] == "pods" {
			break
		}
	}
	//mount name: <podID+volid>
	if i >= len(targetParts) - 1 {
		return "", fmt.Errorf("Didn't find pod ID")
	}
	podID = targetParts[i+1]
	mountName := fmt.Sprintf("%s-%s", podID, volid)
	return mountName, nil
}

func (mounter *csiProxyMounter) NfsMount(
	source, target, fstype string,
	mountOptions, sensitiveMountOptions []string,
) error {
	klog.V(2).Infof("NfsMount: remote path: %s local path: %s", source, target)

	klog.V(2).Infof("NfsMount: other args fsType %s, options %v, %v",
		fstype, mountOptions, sensitiveMountOptions)

	// check if the temp workDir exists, if not create it.
	exists, err := mounter.ExistsPath(workDir)
	if err != nil {
		return fmt.Errorf("work dir: %s exist check failed with err: %v", workDir, err)
	}

	if !exists {
		klog.V(2).Infof("work directory %s does not exists. Creating the directory", workDir)
		if err := mounter.MakeDir(workDir); err != nil {
			return fmt.Errorf("create of work dir: %s failed with error: %v", workDir, err)
		}
	}
	parentDir := filepath.Dir(target)
	parentExists, err := mounter.ExistsPath(parentDir)
	if err != nil {
		return fmt.Errorf("parent dir: %s exist check failed with err: %v", parentDir, err)
	}

	if !parentExists {
		klog.V(2).Infof("Parent directory %s does not exists. Creating the directory", parentDir)
		if err := mounter.MakeDir(parentDir); err != nil {
			return fmt.Errorf("create of parent dir: %s dailed with error: %v", parentDir, err)
		}
	}

	source = normalizeWindowsPath(source, true)
	parts := strings.FieldsFunc(source, Split)
	if len(parts) > 0 && strings.HasSuffix(parts[0], "svc.cluster.local") {
		domainName := parts[0]
		klog.V(2).Infof("begin to replace hostname(%s) with IP for source(%s)", domainName, source)
		ip, err := net.ResolveIPAddr("ip4", domainName)
		if err != nil {
			klog.Warningf("could not resolve name to IPv4 address for host %s, failed with error: %v", domainName, err)
		} else {
			klog.V(2).Infof("resolve the name of host %s to IPv4 address: %s", domainName, ip.String())
			source = strings.Replace(source, domainName, ip.String(), 1)
		}
	}

	klog.V(2).Infof("norm source %v, split %+v", source, parts)

	// 'source' path has to be of form: //<ip>/var/lib/osd/mounts/<volid>
	volid := parts[len(parts)-1]
	normalizedTarget := normalizeWindowsPath(target, false)
	mountName, err := mounter.getMountTargetID(normalizedTarget, volid)
	if err != nil {
		klog.V(2).Infof("begin to add drive vol %s, from %s on %s", volid, source, normalizedTarget)
		return err
	}

	if ok, err := mounter.DriveExists(mountName); err != nil {
		return err
	} else if !ok {
		klog.V(2).Infof("begin to add drive vol %s, from %s on %s", volid, source, mountName)
		err := mounter.AddDrive(volid, source, nil, mountName)

		if err != nil {
			klog.V(2).Infof("Failed to addDrive %s, %s, %s, error(%v)", volid, source, normalizedTarget, err)
			return err
		}
	}
	mountNamePath := volumePath(mountName)
	// symlink the mountName to the targetPath
	klog.V(2).Infof("NfsMount: Creating Symlink from  %s, to %s", mountNamePath, normalizedTarget)
	if err := mounter.MkLink(mountName, normalizedTarget); err != nil {
		klog.V(2).Infof("Failed to addDrive %s, %s, %s, error(%v)", volid, source, normalizedTarget, err)
		return err
	}

	klog.V(2).Infof("NfsMount: Returning successfully")
	return nil
}

func (mounter *csiProxyMounter) NfsUnmount(volumeID string, target string) error {
	klog.V(4).Infof("Unmount: local path: %s", target)
	normalizedTarget := normalizeWindowsPath(target, false)
	mountName, _ := mounter.getMountTargetID(normalizedTarget, volumeID)
	klog.V(2).Infof("begin to Unmount volume %s on %s", volumeID, mountName)
	mounter.RmDrive(volumeID, mountName)
	mounter.RmLink(mountName, normalizedTarget)
	return nil
}

// NewSmbCSIProxyMounter - creates a new CSI Proxy mounter struct which encompassed all the
// clients to the CSI proxy - filesystem, disk and volume clients.
func NewSmbCSIProxyMounter(removeSMBMappingDuringUnmount bool) (*csiProxyMounter, error) {
	return &csiProxyMounter{
		Mode:                          common.DriverModeFlagSmb,
		RemoveSMBMappingDuringUnmount: removeSMBMappingDuringUnmount,
	}, nil
}

func NewNfsCSIProxyMounter() (*csiProxyMounter, error) {
	return &csiProxyMounter{Mode: common.DriverModeFlagNfs, RemoveSMBMappingDuringUnmount: true}, nil
}

func NewSafeMounter(mode string, removeSMBMappingDuringUnmount bool) (*mount.SafeFormatAndMount, error) {
	var csiProxyMounter *csiProxyMounter
	var err error

	if mode == common.DriverModeNfs {
		csiProxyMounter, err = NewNfsCSIProxyMounter()
		if err != nil {
			klog.V(2).Infof("failed to initialize nfs mounter: %v", err)
			return nil, err
		}
		klog.V(2).Infof("using NFS CSIProxyMounterV1")
	} else {
		return nil, fmt.Errorf("unsupported driver mode %v", mode)
	}

	return &mount.SafeFormatAndMount{
		Interface: csiProxyMounter,
		Exec:      utilexec.New(),
	}, nil
}
