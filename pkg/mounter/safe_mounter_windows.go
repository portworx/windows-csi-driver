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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	filepath "path/filepath"
	"strings"

	"github.com/libopenstorage/openstorage/api"
	"github.com/portworx/sched-ops/k8s/core"
	"github.com/portworx/windows-csi-driver/pkg/common"

	//corev1 "k8s.io/api/core/v1"
	"google.golang.org/grpc"
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
	info, err := os.Lstat(normalizeWindowsPath(path, false))
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
	_, err := os.Lstat(normalizeWindowsPath(path, false))
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
	csimode string,
	uuidPath string,
	uuid string,
) error {

	klog.V(2).Infof("AddDrive: volid %s, source %s, uuidPath %s, sensitiveOpts %v",
		volid, share_path, uuidPath, sensitiveMountOptions)

	cmdLine := fmt.Sprintf(`New-PSDrive -Name ${Env:volid} -PSProvider FileSystem ` +
		`-Root ${Env:path} -Scope Global -Description ${Env:pwxtag}`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("volid=%s", uuid),
		fmt.Sprintf("path=%s", share_path),
		fmt.Sprintf("pwxtag=%s", pwxtag))

	if err != nil {
		klog.V(2).Infof("AddDrive: volid %s, cmd %v, failed %v", volid, cmdLine, err)
		return fmt.Errorf("error nfs mounting. cmd %s, output %s. err %v", cmdLine, string(out), err)
	}

	klog.V(2).Infof("Successfully Verified Mount Path %s", share_path)
	_, err = os.Lstat(uuidPath)
	if err == nil {
		os.Remove(uuidPath)
	}

	klog.V(2).Infof("AddDrive: Creating Path from  %s, to %s", uuidPath, share_path)
	cmdLine = fmt.Sprintf("mklink /D %s %s", uuidPath, share_path)
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

func (mounter *csiProxyMounter) MkLink(mountPath, target string) error {
	// runs:
	// New-item -Path c:\myvol\vol1 -ItemType SymbolicLink -Value c:\pwxvol\615688357680565115
	klog.V(2).Infof("MkLink: mountPath %s, target %s", mountPath, target)

	cmdLine := fmt.Sprintf("New-Item -Path ${Env:target} -ItemType SymbolicLink -Value ${Env:workPath}")
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("workPath=%s", mountPath), fmt.Sprintf("target=%s", target))
	if err != nil {
		klog.V(2).Infof("MkLink: mountPath %s, target %s, failed %v", mountPath, target, err)
		return fmt.Errorf("error mkvolume. cmd %s, output %s, err %v", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) RmLink(mountPath, target string) error {
	// runs:
	// Remove-item does not properly remove symlinks, use os.Remove and see if it work
	klog.V(2).Infof("RmLink: volid %s, target %s", mountPath, target)

	err := os.Remove(mountPath)
	if err != os.ErrNotExist {
		klog.V(2).Infof("RmLink: mountPath %s, target %s, failed %v", mountPath, target, err)
		return err
	}

	return nil
}

func (mounter *csiProxyMounter) CheckVolidMounted(volid string) bool {
	dirFiles, err := os.ReadDir(mountDir)
	if err != nil {
		klog.V(2).Infof("Reading mountDir failed [%v]", err)
		return false
	}
	for _, dirEntry := range dirFiles {
		if strings.Contains(dirEntry.Name(), volid) {
			return true
		}
	}
	return false
}

func (mounter *csiProxyMounter) getUUIDFromTargetPath(target, volid string) (string, error) {
	var uuid string
	targetParts := strings.FieldsFunc(target, Split)
	var i int
	for i = 0; i < len(targetParts)-1; i++ {
		if targetParts[i] == "pods" {
			break
		}
	}
	if i >= len(targetParts)-1 {
		return "", fmt.Errorf("Didn't find UUID in target path")
	}
	uuid = targetParts[i+1]
	return uuid, nil
}

func (mounter *csiProxyMounter) getMountTargetID(podID, volid string) string {
	mountName := fmt.Sprintf("%s_%s", volid, podID)
	return mountName
}

func (mounter *csiProxyMounter) createWorkDirectories() error {
	// check if the temp workDir exists, if not create it.
	exists, err := mounter.ExistsPath(mountDir)
	if err != nil {
		return fmt.Errorf("mount dir: %s exist check failed with err: %v", mountDir, err)
	}

	if !exists {
		klog.V(2).Infof("mount directory %s does not exists. Creating the directory", mountDir)
		if err := mounter.MakeDir(mountDir); err != nil {
			return fmt.Errorf("create of internal work dir: %s failed with error: %v", mountDir, err)
		}
	}

	exists, err = mounter.ExistsPath(mountInfoDir)
	if err != nil {
		return fmt.Errorf("mountInfo dir: %s exist check failed with err: %v", mountInfoDir, err)
	}

	if !exists {
		klog.V(2).Infof("uuid directory %s does not exists. Creating the directory", mountInfoDir)
		if err := mounter.MakeDir(mountInfoDir); err != nil {
			return fmt.Errorf("create of internal work dir: %s failed with error: %v", mountInfoDir, err)
		}
	}
	return nil
}

func (mounter *csiProxyMounter) writeMountInfoFile(volumeID, endpoint, podID, podName, podNamespace string) error {
	mountInfoFilePath := getMountInfoPath(volumeID, podID)
	file, err := os.OpenFile(mountInfoFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		klog.V(2).Infof("Creating mountInfoFile[%s] failed with error[%v]", mountInfoFilePath, err)
		return err
	}
	defer file.Close()
	str := fmt.Sprintf("VolumeID=%s", volumeID)
	file.WriteString(str + "\n")
	str = fmt.Sprintf("EndPoint=%s", endpoint)
	file.WriteString(str + "\n")
	str = fmt.Sprintf("PodUID=%s", podID)
	file.WriteString(str + "\n")
	str = fmt.Sprintf("PodName=%s", podName)
	file.WriteString(str + "\n")
	str = fmt.Sprintf("PodNamespace=%s", podNamespace)
	file.WriteString(str + "\n")
	return nil
}

func (mount *csiProxyMounter) removeMountInfoFile(volumeID, podID string) {
	mountInfoFilePath := getMountInfoPath(volumeID, podID)
	os.Remove(mountInfoFilePath)
	return
}

func (mounter *csiProxyMounter) NfsMount(
	source, target, fstype, endpoint, podID string,
	podName, podNamespace string,
	mountOptions, sensitiveMountOptions []string,
) error {
	klog.V(2).Infof("NfsMount: remote path: %s local path: %s", source, target)

	klog.V(2).Infof("NfsMount: other args fsType %s, options %v, %v",
		fstype, mountOptions, sensitiveMountOptions)

	if err := mounter.createWorkDirectories(); err != nil {
		return err
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
	volid := parts[len(parts)-1]
	if endpoint == "" {
		endpoint = parts[0]
	}

	// 'source' path has to be of form: //<ip>/var/lib/osd/mounts/<volid>

	//
	// Order of Creation
	// Lock : Function under volid Lock, so no concurrency issues.
	// There is no race with a parallel creation/deletion.
	// 1. podIDPath => normalizedTargetPath
	// 2. normalizedTargetPath => source.
	// 3. UUIDPath => podIDPath.

	//
	// Error at step 1: return.
	// At Step 2: Remove podIDPath
	// At Step 3: Remove targetPath, recreate DiR if needed.
	// Post Step 3; Remove 3, 2, 1

	normalizedTarget := normalizeWindowsPath(target, false)

	if podID == "" {
		if uuid, err := mounter.getUUIDFromTargetPath(target, volid); err != nil {
			klog.V(2).Infof("Cannot get UUID for Target Path[%s] err[%v]", normalizedTarget, err)
			return err
		} else {
			podID = uuid
		}
	}

	if podName != "" && podNamespace != "" {
		if err := mounter.writeMountInfoFile(volid, endpoint, podID, podName, podNamespace); err != nil {
			klog.V(2).Infof("Failed to write MountInfo file for volid[%s] podID[%s] source[%s] target[%s] err[%v]",
				volid, podID, source, normalizedTarget, err)
		} else {
			klog.V(5).Infof("Wrote MountInfo file for volid[%s] podID[%s] source[%s] target[%s] successfully",
				volid, podID, source, normalizedTarget)
		}
	}
	mountName := mounter.getMountTargetID(podID, volid)
	if err != nil {
		klog.V(2).Infof("begin to add drive vol %s, from %s on %s", volid, source, normalizedTarget)
		return err
	}

	uuidPath := getMountPath(volid, podID)
	klog.V(2).Infof("NfsMount: Creating Symlink from  %s, to %s", uuidPath, normalizedTarget)

	if ok, err := mounter.DriveExists(mountName); err != nil {
		return err
	} else if !ok {
		klog.V(2).Infof("begin to add drive vol %s, from %s on %s", volid, source, mountName)
		err := mounter.AddDrive(volid, source, nil, "nfs", uuidPath, podID)

		if err != nil {
			klog.V(2).Infof("Failed to addDrive %s, %s, %s, error(%v)", volid, source, normalizedTarget, err)
			mounter.removeMountInfoFile(volid, podID)
			return err
		}
	}

	if err := mounter.MkLink(uuidPath, normalizedTarget); err != nil {
		klog.V(2).Infof("Failed to create uuid Link from %s, %s, error(%v)", uuidPath, normalizedTarget, err)
		mounter.RmDrive(volid, mountName)
		mounter.RmLink(uuidPath, normalizedTarget)
		mounter.removeMountInfoFile(volid, podID)
		return err
	}

	klog.V(2).Infof("NfsMount: Returning successfully")
	return nil
}

func (mounter *csiProxyMounter) NfsUnmount(volumeID string, target string) error {
	klog.V(4).Infof("NfsUnmount: local path: %s", target)

	normalizedTarget := normalizeWindowsPath(target, false)
	var err error
	var podID string
	if podID, err = mounter.getUUIDFromTargetPath(target, volumeID); err != nil {
		klog.V(2).Infof("Cannot get UUID for Target Path[%s] err[%v]", normalizedTarget, err)
	}
	mountName := mounter.getMountTargetID(volumeID, podID)
	klog.V(2).Infof("begin to Unmount volume %s on %s", volumeID, mountName)
	mounter.RmDrive(volumeID, mountName)
	uuidPath := getMountPath(volumeID, podID)
	mounter.RmLink(uuidPath, normalizedTarget)
	mounter.removeMountInfoFile(volumeID, podID)
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

func (mounter *csiProxyMounter) readMountInfoFile(volumeID, uuid string) (string, string, string, string, string, error) {
	// The mount point is Stale now, need to restart the pod.
	// Read the mountInfo.
	mountInfoPath := getMountInfoPath(volumeID, uuid)
	file, err := os.Open(mountInfoPath)
	if err != nil {
		klog.V(2).Infof("Reading mountInfoFile[%s] failed with error[%v]", mountInfoPath, err)
		return "", "", "", "", "", err
	}
	defer file.Close()
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)

	var podName string
	var podNamespace string
	var volume string
	var fileEndpoint string
	var podUID string

	for fileScanner.Scan() {
		line := fileScanner.Text()
		lineParts := strings.Split(line, "=")
		switch lineParts[0] {
		case "PodName":
			podName = lineParts[1]
		case "PodUID":
			podUID = lineParts[1]
		case "EndPoint":
			fileEndpoint = lineParts[1]
		case "VolumeID":
			volume = lineParts[1]
		case "PodNamespace":
			podNamespace = lineParts[1]
		default:
			klog.V(2).Infof("Unexpcted Line found")
		}
	}
	return podName, podNamespace, podUID, volume, fileEndpoint, nil
}

func (mounter *csiProxyMounter) ReadSavedData(volumeID, targetPath string) (string, string, string, string, string, error) {
	uuid, err := mounter.getUUIDFromTargetPath(targetPath, volumeID)
	if err == nil {
		return mounter.readMountInfoFile(volumeID, uuid)
	}
	return "", "", "", "", "", err
}

func (mounter *csiProxyMounter) restartManagedPods(volumeClient api.OpenStorageVolumeClient, volumeID, uuid string) {
	podName, podNamespace, podUID, volume, fileEndpoint, err := mounter.readMountInfoFile(volumeID, uuid)
	if err == nil {
		klog.V(7).Infof("MountInfoPath Contents <%s,%s,%s,%s.,%s>", podName, podNamespace, podUID, fileEndpoint, volume)
		if podName != "" && podNamespace != "" {
			pod, err := core.Instance().GetPodByName(podName, podNamespace)
			if err != nil {
				klog.V(2).Infof("Failed to get pod by Name for [%s, %s], err[%v]", podName, podNamespace, err)
				return
			}
			if core.Instance().IsPodBeingManaged(*pod) {
				if pod.DeletionTimestamp == nil {
					err = core.Instance().DeletePod(podName, podNamespace, false)
					if err == nil {
						klog.V(2).Infof("Successfully bounced pod [%s, %s]", podName, podNamespace)
					}
				}

			} else {
				klog.V(2).Infof("Skipping bouncing of pod [%s, %s] as it is not Managed", podName, podNamespace)
			}
		}
	}
	return
}

func (mounter *csiProxyMounter) BackGroundMountProcess(ipAddr string) {
	exportMap := make(map[string][]string)
	_, err := os.Stat(mountDir)
	if err == nil {
		file, err := os.Open(mountDir)
		if err == nil {
			names, err := file.Readdirnames(0)
			if err == nil {
				for _, name := range names {
					filePath := fmt.Sprintf("%s\\%s", mountDir, name)
					stat, statErr := os.Lstat(filePath)
					if statErr != nil {
						klog.V(2).Infof("BMP: Stat of [%s] failed, err[%v]", filePath, statErr)
						continue
					}
					if (stat.Mode() & os.ModeSymlink) == os.ModeSymlink {
						readLink, err := os.Readlink(filePath)
						if err != nil {
							klog.V(2).Infof("BMP: Readlink of [%s] failed, err[%v]", filePath, err)
							continue
						}
						_,ok := exportMap[readLink]
						if !ok {
							str := make([]string, 0)
							exportMap[readLink] = str
							exportMap[readLink] = append(exportMap[readLink], name)
						} else {
							exportMap[readLink] = append(exportMap[readLink], name)
						}
					} else {
						klog.V(2).Infof("BMP: Non Symlink file found [%s]", filePath)
					}
				}
			}
		}
	}
	if len(exportMap) > 0 {
		conn, err := grpc.Dial(ipAddr, grpc.WithInsecure())
		if err != nil {
			klog.V(2).Infof("BackgroundMountProcess: Couldn't open rpc connection to [%s], err[%v]", ipAddr, err)
			return
		}
		defer conn.Close()
		clusterClient := api.NewOpenStorageClusterClient(conn)

		clusterInfo, err := clusterClient.InspectCurrent(context.TODO(), &api.SdkClusterInspectCurrentRequest{})
		if err == nil {
			klog.V(2).Infof("BackgroundMountProcess: clusterInfo[%v]", clusterInfo)
		}
		volumeClient := api.NewOpenStorageVolumeClient(conn)
		for readLink, nameMap := range exportMap {
			linkParts := strings.FieldsFunc(readLink, Split)
			// IP Address => linkParts [0]
			// volumeID => linkParts[n-1]
			targetIPAddr := linkParts[0]
			volumeID := linkParts[len(linkParts) - 1]
			klog.V(7).Infof("BMP: Link[%v]", readLink)
			volInfo, err := volumeClient.Inspect(context.TODO(), &api.SdkVolumeInspectRequest{VolumeId: volumeID})
			if err != nil {
				klog.V(2).Infof("BMP: volumeID[%v] targetIPAddr[%s] Inspect failed. Error[%v]", volumeID, targetIPAddr, err)
				continue
			}
			if volInfo.GetVolume().GetAttachedOn() != targetIPAddr {
				// All the pods needs to be restarted.
				for _,name := range nameMap {
					var nameVolumeID string
					var uuid string
					fileNameparts := strings.Split(name, "_")
					if len(fileNameparts) == 2 {
						nameVolumeID = fileNameparts[0]
						uuid = fileNameparts[1]
					} else {
						klog.V(2).Infof("BMP: Filename not in specified format [%s]", name)
						continue
					}
					mounter.restartManagedPods(volumeClient, nameVolumeID, uuid)
				}
			}
		}
	}
	return
}
