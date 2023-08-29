package portworx

import (
	"github.com/portworx/windows-csi-driver/pkg/common"
	iscsi "github.com/portworx/windows-csi-driver/pkg/iscsi"
	nfs "github.com/portworx/windows-csi-driver/pkg/nfs"
	smb "github.com/portworx/windows-csi-driver/pkg/smb"
	"k8s.io/klog/v2"
)

// NewDriver Creates a NewCSIDriver object. Assumes vendor version is equal to driver version &
// does not support optional driver plugin info manifest field. Refer to CSI spec for more details.
func NewDriver(name, version string, options *common.DriverOptions) common.BaseDriver {
	switch options.Mode {
	case common.DriverModeFlagNfs:
		klog.V(2).Info("\nDRIVER initialized with Nfs\n")
		return nfs.NewDriver(name, version, options)
	case common.DriverModeFlagSmb:
		klog.V(2).Info("\nDRIVER initialized with Smb\n")
		return smb.NewDriver(name, version, options)
	case common.DriverModeFlagIscsi:
		klog.V(2).Info("\nDRIVER initialized with iscsi\n")
		return iscsi.NewDriver(name, version, options)
	default:
		klog.V(2).Info("\nDRIVER initialized with iscsi\n")
		return nil
	}

}
