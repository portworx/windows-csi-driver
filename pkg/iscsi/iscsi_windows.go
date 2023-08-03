//go:build windows
// +build windows

package iscsi

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/portworx/windows-csi-driver/pkg/mounter"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	klog "k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
)

// information needed to setup iscsi connection successfully
type iscsiDisk struct {
	volumeID string
	portals  []string // ip:port
	iqn      string
	lun      int32
	iface    string

	serial_number       string
	authentication_type string

	chapDiscovery   bool
	chapSession     bool
	secret          map[string]string
	enableMultiPath bool
}

func parsePortal(portal string) (string, uint32) {
	var addr string
	var port int

	fields := strings.Split(portal, ":")
	addr = fields[0]
	port, _ = strconv.Atoi(fields[1])

	return addr, uint32(port)
}

func getNeededAttributes(volumeID string, context map[string]string) *iscsiDisk {
	type attribs struct {
		volumeID            string
		protocol            string
		tp_addr             string
		tp_port             string
		iqn                 string
		lun                 string
		serial_number       string
		authentication_type string
		device_path         string
		node_id             string

		readonly string
	}

	var attrs attribs
	for k, v := range context {
		klog.V(2).Infof("[%s]: Parsing %s: %v", volumeID, k, v)
		switch k {
		case "volumeID":
			attrs.volumeID = v
			if v != volumeID {
				klog.Fatalf("volume(%v) context found mismatch volume attribute(%v:%v)", volumeID, k, v)
			}
		case "protocol":
			attrs.protocol = v
		case "target_node_address":
			attrs.tp_addr = v
		case "target_node_port":
			attrs.tp_port = v
		case "iqn":
			attrs.iqn = v
		case "lun":
			attrs.lun = v
		case "serial_number":
			attrs.serial_number = v
		case "authentication_type":
			attrs.authentication_type = v
		case "device_path":
			attrs.device_path = v
		case "node_id":
			attrs.node_id = v
		case "readonly":
			attrs.readonly = v
		default:
			// unknown k/v found in context from controller.
			klog.Warningf("volume(%v) context found unknown attribute(%v:%v)", volumeID, k, v)
		}
	}

	disk := iscsiDisk{}

	disk.volumeID = volumeID
	portal := fmt.Sprintf("%s:%s", attrs.tp_addr, attrs.tp_port)
	disk.portals = append(disk.portals, portal)
	disk.iqn = attrs.iqn
	disk.lun = 0
	if v, e := strconv.ParseUint(attrs.lun, 10, 32); e == nil {
		disk.lun = int32(v)
	}
	disk.serial_number = attrs.serial_number
	disk.authentication_type = attrs.authentication_type
	disk.iface = "default"

	// authentication other than none - not supported

	klog.V(2).Infof("volume %v: disk info{%+v}", volumeID, disk)
	return &disk
}

func volHigh(id uint64) uint64 {
	return id >> 48
}

func volLow(id uint64) uint64 {
	return id & 0xffffffffffff
}

func getVolumeWWN(volumeID string) (string, error) {
	// volumeID - pwx unique volume id ex. 425350735095133013
	const volIDFmt = "504f5258-0000-0102-%04x-%012x"

	id, err := strconv.ParseUint(volumeID, 10, 64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(volIDFmt, volHigh(id), volLow(id)), nil
}

func csiMounter(m mount.Interface) mounter.CSIProxyMounter {
	p, ok := m.(*mount.SafeFormatAndMount)
	if !ok {
		klog.Fatalf("cannot dereference to needed mount.SafeFormatAndMount")
	}

	p1, ok := p.Interface.(mounter.CSIProxyMounter)
	if !ok {
		klog.Fatalf("cannot dereference to needed CSIProxyMounter")
	}
	return p1
}

func (ns *iscsiDriver) addDisk(disk *iscsiDisk) error {
	// ns.mounter has the csi-proxy handle to talk to host

	for _, p := range disk.portals {
		addr, port := parsePortal(p)
		klog.V(2).Infof("%s: addDisk: portal %s, parsed addr %v, port %v", disk.volumeID, p, addr, port)
		if err := csiMounter(ns.mounter).IscsiAddTargetPortal(addr, port); err != nil {
			return err
		}

		if err := csiMounter(ns.mounter).IscsiConnectTargetNoAuth(addr, port, disk.iqn); err != nil { // no auth
			return err
		}
	}

	wwn, err := getVolumeWWN(disk.volumeID)
	if err != nil {
		return err
	}

	/// not expected!!!
	if wwn != disk.serial_number {
		klog.Fatalf("volume(%v) context has wwn mismatch want/has (%v:%v)", disk.volumeID, wwn, disk.serial_number)
	}

	m := csiMounter(ns.mounter)

	err = m.IscsiFormatVolume(disk.serial_number, disk.volumeID)
	if err != nil {
		return err
	}

	klog.V(2).Infof("Volume(%v) successfully setup", disk.volumeID)
	return nil
}

func (ns *iscsiDriver) iscsiNodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	// connect discover and login to create a local disk.
	// if disk raw, then initialize and create needed partition, then format the volume..
	// mount the volume to the stage path, and add a reference
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}

	// this is where the disk is to be attached.
	targetPath := req.GetStagingTargetPath()
	if len(targetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Staging target not provided")
	}

	// context is setup by pwx csi controller driver
	context := req.GetPublishContext()

	disk := getNeededAttributes(volumeID, context)

	// use 'disk' to create an iscsi session and import the volume
	// perform needed format if necessary
	// attach the disk to the given staging path
	err := ns.addDisk(disk)
	if err != nil {
		return nil, err
	}

	// mountFlags := req.GetVolumeCapability().GetMount().GetMountFlags()
	// volumeMountGroup := req.GetVolumeCapability().GetMount().GetVolumeMountGroup()
	// secrets := req.GetSecrets()
	// gidPresent := checkGidPresentInMountFlags(mountFlags)
	m := csiMounter(ns.mounter)

	paths, err := m.IscsiGetVolumeMounts(disk.volumeID, false)
	if err != nil {
		return nil, err
	}

	for _, p := range paths {
		if p == targetPath {
			return &csi.NodeStageVolumeResponse{}, nil
		}
	}

	err = m.IscsiVolumeMount(disk.volumeID, targetPath)
	if err != nil {
		return nil, err
	}

	return &csi.NodeStageVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	// drop a reference to the volume, if goes to zero, then perform cleanup
	klog.V(2).Infof("Volume(%v) NodeUnstageVolume from path %v", req.GetVolumeId(), req.GetStagingTargetPath())

	m := csiMounter(ns.mounter)

	/*
		paths, err := m.IscsiGetVolumeMounts(req.GetVolumeId(), false)
		if err != nil {
			return nil, err
		}

		targetPath := req.GetStagingTargetPath()
		found := false
		for _, p := range paths {
			if p == targetPath {
				found = true
				break
			}
		}

		if !found {
			return &csi.NodeUnstageVolumeResponse{}, nil
		}
	*/

	// dont fail this call, do as much cleanup as possible, report failures as logs
	coe := true

	err := m.IscsiVolumeUnmount(req.GetVolumeId(), req.GetStagingTargetPath())
	if err != nil {
		if !coe {
			return nil, err
		}
		klog.Warning("Volume(%v) unmount failed %s", req.GetVolumeId(), err)
	}

	iqn, err := m.IscsiGetTargetNodeAddress(req.GetVolumeId())
	if err != nil {
		if !coe {
			return nil, err
		}
		klog.Warningf("Volume(%v) target node addr failed %s", req.GetVolumeId(), err)
	} else {
		klog.V(2).Infof("Volume(%v) found matching iqn %s", req.GetVolumeId(), iqn)
		err = m.IscsiDisconnectTarget(iqn)
		if err != nil {
			return nil, err
		}
	}

	klog.V(2).Infof("Volume(%v) NodeUnstageVolume from path %v, iqn %s finished err = %v",
		req.GetVolumeId(), req.GetStagingTargetPath(), iqn, err)
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	// bind mount the volume from stage path to target path
	m := csiMounter(ns.mounter)

	paths, err := m.IscsiGetVolumeMounts(req.GetVolumeId(), false)
	if err != nil {
		return nil, err
	}

	targetPath := req.GetTargetPath()
	for _, p := range paths {
		if p == targetPath {
			return &csi.NodePublishVolumeResponse{}, nil
		}
	}

	err = m.IscsiVolumeMount(req.GetVolumeId(), targetPath)
	if err != nil {
		return nil, err
	}

	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	// unmount from target path, decr ref for volume.
	klog.V(2).Infof("Volume(%v) NodeUnpublishVolume from path %v", req.GetVolumeId(), req.GetTargetPath())

	m := csiMounter(ns.mounter)

	targetPath := req.GetTargetPath()
	/*
		--- Do not fail call if volume does not exist!
		paths, err := m.IscsiGetVolumeMounts(req.GetVolumeId(), false)
		if err != nil {
			return nil, err
		}

		for _, p := range paths {
			if p == targetPath {
	*/
	{
		{
			err := m.IscsiVolumeUnmount(req.GetVolumeId(), targetPath)
			klog.V(2).Infof("Volume(%v) NodeUnpublishVolume from path %v finished err = %v",
				req.GetVolumeId(), targetPath, err)
			return &csi.NodeUnpublishVolumeResponse{}, err
		}
	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}
