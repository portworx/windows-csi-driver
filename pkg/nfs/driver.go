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
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/portworx/windows-csi-driver/pkg/common"
	csicommon "github.com/portworx/windows-csi-driver/pkg/csi-common"
	klog "k8s.io/klog/v2"

	"github.com/portworx/windows-csi-driver/pkg/mounter"
	"github.com/portworx/windows-csi-driver/pkg/utils"
	mount "k8s.io/mount-utils"
)

type nfsDriver struct {
	csicommon.CSIDriver
	mounter mount.Interface

	// A map storing all volumes with ongoing operations so that additional operations
	// for that same volume (as defined by VolumeID) return an Aborted error
	volumeLocks *utils.VolumeLocks

	enableGetVolumeStats bool   // whether stats on volume is available - not supported
	endpoint             string // csi socket end point to receive/respond to reqs
}

func NewDriver(name, version string, options *common.DriverOptions) *nfsDriver {
	d := nfsDriver{}
	klog.V(1).Infof("nfsDriver: %s version: %s nodeID: %s endpoint: %s", name, version, options.NodeID,
		options.Endpoint)

	d.Name = name
	d.Version = version
	d.NodeID = options.NodeID

	d.volumeLocks = utils.NewVolumeLocks()
	d.enableGetVolumeStats = options.EnableGetVolumeStats
	d.endpoint = options.Endpoint

	if d.NodeID == "" {
		klog.Fatalf("NodeID mandatory field")
	}

	// why is this needed?
	if err := os.MkdirAll(fmt.Sprintf("/var/run/%s", options.DriverName), 0o755); err != nil {
		panic(err)
	}
	d.AddVolumeCapabilityAccessModes([]csi.VolumeCapability_AccessMode_Mode{
		csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER,
		csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER,
		csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY,
		csi.VolumeCapability_AccessMode_MULTI_NODE_SINGLE_WRITER,
		csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER,
	})
	// Nfs plugin does not support ControllerServiceCapability now.
	// If support is added, it should set to appropriate
	// ControllerServiceCapability RPC types.
	d.AddControllerServiceCapabilities([]csi.ControllerServiceCapability_RPC_Type{csi.ControllerServiceCapability_RPC_UNKNOWN})

	nodeCap := []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_SINGLE_NODE_MULTI_WRITER,
		csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP,
	}
	if d.enableGetVolumeStats {
		nodeCap = append(nodeCap, csi.NodeServiceCapability_RPC_GET_VOLUME_STATS)
	}
	d.AddNodeServiceCapabilities(nodeCap)

	// CHECK if this is needed for nfs
	var err error
	d.mounter, err = mounter.NewSafeMounter(common.DriverModeNfs, false)
	if err != nil {
		klog.Fatalf("Failed to get safe mounter. Error: %v", err)
	}

	return &d
}

func (d *nfsDriver) GetMode() common.DriverModeFlag {
	return common.DriverModeFlagNfs
}

func (d *nfsDriver) Init() {
}

func (d *nfsDriver) GetControllerServer() csi.ControllerServer {
	return d
}

func (d *nfsDriver) GetIdentityServer() csi.IdentityServer {
	return d
}

func (d *nfsDriver) GetNodeServer() csi.NodeServer {
	return d
}
