package portworx

import (
	"github.com/portworx/windows-csi-driver/pkg/common"
	nfs "github.com/portworx/windows-csi-driver/pkg/nfs"
	"k8s.io/klog/v2"
)

// NewDriver Creates a NewCSIDriver object. Assumes vendor version is equal to driver version &
// does not support optional driver plugin info manifest field. Refer to CSI spec for more details.
func NewDriver(name, version string, options *common.DriverOptions) common.BaseDriver {
	switch options.Mode {
	case common.DriverModeFlagNfs:
		klog.V(2).Info("\nDRIVER initialized with Nfs\n")
		return nfs.NewDriver(name, version, options)
	default:
		klog.V(2).Info("\nDRIVER initialized with iscsi\n")
		return nil
	}

}
