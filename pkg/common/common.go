package common

import (
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
)

// common types and definitions for all driver types

type DriverModeFlag uint

const (
	DriverModeFlagInvalid = DriverModeFlag(0)
	DriverModeFlagSmb     = DriverModeFlag(1)
	DriverModeFlagIscsi   = DriverModeFlag(2)
	DriverModeFlagNfs     = DriverModeFlag(3)
)

func (m DriverModeFlag) String() string {
	switch m {
	case DriverModeFlagSmb:
		return "smb"
	case DriverModeFlagNfs:
		return "nfs"
	case DriverModeFlagIscsi:
		return "iscsi"
	default:
		return "invalid"
	}
}

func ParseDriverMode(mode string) (DriverModeFlag, error) {
	switch mode {
	case "iscsi":
		return DriverModeFlagIscsi, nil
	case "smb":
		return DriverModeFlagSmb, nil
	case "nfs":
		return DriverModeFlagNfs, nil
	default:
		return DriverModeFlagInvalid, fmt.Errorf("invalid mode %s", mode)
	}
}

type SmbDriverOptions struct {
	// this only applies to Windows node
	RemoveSMBMappingDuringUnmount bool
}

type IscsiDriverOptions struct {
}

type NfsDriverOptions struct {
	Persist bool
}

// DriverOptions defines driver parameters specified in driver deployment
type DriverOptions struct {
	NodeID     string
	DriverName string
	Mode       DriverModeFlag
	Endpoint   string // csi end point
	WorkDir    string // top level work directory

	EnableGetVolumeStats bool // use metrics server endpoint

	SmbOpts   SmbDriverOptions
	IscsiOpts IscsiDriverOptions
	NfsOpts   NfsDriverOptions
}

type BaseDriver interface {
	ValidateControllerServiceRequest(c csi.ControllerServiceCapability_RPC_Type) error
	ValidateNodeServiceRequest(c csi.NodeServiceCapability_RPC_Type) error
	AddControllerServiceCapabilities(cl []csi.ControllerServiceCapability_RPC_Type)
	AddNodeServiceCapabilities(nl []csi.NodeServiceCapability_RPC_Type)
	AddVolumeCapabilityAccessModes(vc []csi.VolumeCapability_AccessMode_Mode) []*csi.VolumeCapability_AccessMode
	GetVolumeCapabilityAccessModes() []*csi.VolumeCapability_AccessMode

	Init()
	GetMode() DriverModeFlag

	GetControllerServer() csi.ControllerServer
	GetIdentityServer() csi.IdentityServer
	GetNodeServer() csi.NodeServer
}
