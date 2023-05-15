/*
Copyright 2019 The Kubernetes Authors.

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

package smb

import (
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"

	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"

	"github.com/sulakshm/csi-driver/pkg/common"
	csicommon "github.com/sulakshm/csi-driver/pkg/csi-common"
	"github.com/sulakshm/csi-driver/pkg/mounter"
	utils "github.com/sulakshm/csi-driver/pkg/utils"
)

const (
	defaultDomainName = "AZURE"
)

// smbDriver implements all interfaces of CSI drivers
type smbDriver struct {
	csicommon.CSIDriver
	mounter *mount.SafeFormatAndMount
	// A map storing all volumes with ongoing operations so that additional operations
	// for that same volume (as defined by VolumeID) return an Aborted error
	volumeLocks          *utils.VolumeLocks
	workingMountDir      string
	enableGetVolumeStats bool
	// this only applies to Windows node
	removeSMBMappingDuringUnmount bool
}

// NewDriver Creates a NewCSIDriver object. Assumes vendor version is equal to driver version &
// does not support optional driver plugin info manifest field. Refer to CSI spec for more details.
func NewDriver(name, version string, options *common.DriverOptions) *smbDriver {
	driver := smbDriver{}
	driver.Name = name
	driver.Version = version
	driver.NodeID = options.NodeID
	driver.enableGetVolumeStats = options.EnableGetVolumeStats

	if driver.NodeID == "" {
		klog.Fatalf("NodeID mandatory field")
	}

	driver.removeSMBMappingDuringUnmount = options.SmbOpts.RemoveSMBMappingDuringUnmount
	driver.workingMountDir = options.WorkDir

	driver.volumeLocks = utils.NewVolumeLocks()

	var err error
	driver.mounter, err = mounter.NewSafeMounter(common.DriverModeSmb, false, driver.removeSMBMappingDuringUnmount)
	if err != nil {
		klog.Fatalf("Failed to get safe mounter. Error: %v", err)
	}

	// Initialize default library driver
	driver.AddControllerServiceCapabilities(
		[]csi.ControllerServiceCapability_RPC_Type{
			csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
			csi.ControllerServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
		})

	driver.AddVolumeCapabilityAccessModes([]csi.VolumeCapability_AccessMode_Mode{
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER,
		csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER,
		csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER,
	})

	nodeCap := []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
		csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP,
	}
	if driver.enableGetVolumeStats {
		nodeCap = append(nodeCap, csi.NodeServiceCapability_RPC_GET_VOLUME_STATS)
	}
	driver.AddNodeServiceCapabilities(nodeCap)
	return &driver
}

func (d *smbDriver) GetControllerServer() csi.ControllerServer {
	return d
}

func (d *smbDriver) GetIdentityServer() csi.IdentityServer {
	return d
}

func (d *smbDriver) GetNodeServer() csi.NodeServer {
	return d
}

func (d *smbDriver) GetMode() common.DriverModeFlag {
	return common.DriverModeFlagSmb
}

// Init driver initialization
func (d *smbDriver) Init() {
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
