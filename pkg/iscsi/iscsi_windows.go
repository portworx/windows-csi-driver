//go:build windows
// +build windows

package iscsi

import (
	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (ns *iscsiDriver) iscsiNodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	// connect discover and login to create a local disk.
	// if disk raw, then initialize and create needed partition, then format the volume..
	// mount the volume to the stage path, and add a reference

	return &csi.NodeStageVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	// drop a reference to the volume, if goes to zero, then perform cleanup
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	// bind mount the volume from stage path to target path
	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *iscsiDriver) iscsiNodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	// unmount from target path, decr ref for volume.
	return &csi.NodeUnpublishVolumeResponse{}, nil
}
