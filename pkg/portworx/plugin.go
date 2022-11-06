package portworx

import (
	"k8s.io/klog/v2"

	"github.com/sulakshm/csi-driver/pkg/common"
	smb "github.com/sulakshm/csi-driver/pkg/smb"
	iscsi "github.com/sulakshm/csi-driver/pkg/iscsi"
)

const (
	DefaultDriverName    = "pxd.portworx.com"
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
	driverModeSmb       = "smb"
        driverModeIscsi     = "iscsi"
)

// NewDriver Creates a NewCSIDriver object. Assumes vendor version is equal to driver version &
// does not support optional driver plugin info manifest field. Refer to CSI spec for more details.
func NewDriver(name, version string, options *common.DriverOptions) common.BaseDriver {
	if options.Mode == common.DriverModeSmb {
		klog.V(2).Info("\nDRIVER initialized with Smb\n")
		return smb.NewDriver(name, version, options)
	}

	klog.V(2).Info("\nDRIVER initialized with iscsi\n")
	return iscsi.NewDriver(name, version, options)
}
