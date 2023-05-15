package common

const (
	DefaultDriverName = "pxd.portworx.com"

	UsernameField     = "username"
	PasswordField     = "password"
	SourceField       = "source"
	SubDirField       = "subdir"
	DomainField       = "domain"
	MountOptionsField = "mountoptions"
	DefaultDomainName = "AZURE"

	PvcNameKey           = "csi.storage.k8s.io/pvc/name"
	PvcNamespaceKey      = "csi.storage.k8s.io/pvc/namespace"
	PvNameKey            = "csi.storage.k8s.io/pv/name"
	PvcNameMetadata      = "${pvc.metadata.name}"
	PvcNamespaceMetadata = "${pvc.metadata.namespace}"
	PvNameMetadata       = "${pv.metadata.name}"

	DriverModeSmb   = "smb"
	DriverModeIscsi = "iscsi"
	DriverModeNfs   = "nfs"

	CsimodeField = "csimode" // one of "nfs" "smb" or "iscsi"

	ShareField       = "shareKey"       // share name
	SharePathField   = "sharePathKey"   // remote share path
	EndpointField    = "endpointKey"    // remote endpoint
	SvcEndpointField = "svcEndpointKey" // remote service endpoint
)
