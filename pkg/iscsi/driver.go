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

package iscsi

import (
	"fmt"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/portworx/windows-csi-driver/pkg/common"
	csicommon "github.com/portworx/windows-csi-driver/pkg/csi-common"
	klog "k8s.io/klog/v2"

	"github.com/portworx/windows-csi-driver/pkg/mounter"
	mount "k8s.io/mount-utils"
)

type iscsiDriver struct {
	csicommon.CSIDriver
	mounter mount.Interface

	enableGetVolumeStats bool
	endpoint             string
}

var driverName string

func NewDriver(name, version string, options *common.DriverOptions) *iscsiDriver {
	d := iscsiDriver{}
	klog.V(1).Infof("iscsiDriver: %s version: %s nodeID: %s endpoint: %s", name, version, options.NodeID,
		options.Endpoint)

	d.Name = name
	d.Version = version
	d.NodeID = options.NodeID
	d.enableGetVolumeStats = options.EnableGetVolumeStats
	d.endpoint = options.Endpoint

	driverName = name

	if d.NodeID == "" {
		klog.Fatalf("NodeID mandatory field")
	}

	if err := os.MkdirAll(fmt.Sprintf("/var/run/%s", options.DriverName), 0o755); err != nil {
		panic(err)
	}
	d.AddVolumeCapabilityAccessModes([]csi.VolumeCapability_AccessMode_Mode{csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER})
	// iSCSI plugin does not support ControllerServiceCapability now.
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

	var err error
	d.mounter, err = mounter.NewSafeMounter(common.DriverModeIscsi, options.NfsOpts.Persist, false)
	if err != nil {
		klog.Fatalf("Failed to get safe mounter. Error: %v", err)
	}

	return &d
}

func (d *iscsiDriver) GetMode() common.DriverModeFlag {
	return common.DriverModeFlagIscsi
}

func (d *iscsiDriver) Init() {
}

func (d *iscsiDriver) GetControllerServer() csi.ControllerServer {
	return d
}

func (d *iscsiDriver) GetIdentityServer() csi.IdentityServer {
	return d
}

func (d *iscsiDriver) GetNodeServer() csi.NodeServer {
	return d
}
