package mounter

import (
	"context"
	"fmt"

	iscsi "github.com/kubernetes-csi/csi-proxy/client/api/iscsi/v1alpha2"
)

type IscsiMounter interface {
	///  Iscsi specifics
	IscsiAddTargetPortal(ctx context.Context, addr string, port uint32) error
	IscsiConnectTargetNoAuth(ctx context.Context, addr string, port uint32, iqn string) error
	IscsiDisconnectTarget(ctx context.Context, iqn string) error
	IscsiDiscoverTargetPortal(ctx context.Context, addr string, port uint32) ([]string, error)
	IscsiListTargetPortals(ctx context.Context) ([]iscsi.TargetPortal, error)
	IscsiRemoveTargetPortal(ctx context.Context, addr string, port uint32) error
	IscsiVolumeExists(ctx context.Context, fsLabel string) (bool, error)
	IscsiDiskInitialized(ctx context.Context, serialnum string) (bool, error)
	IscsiDiskInit(ctx context.Context, serialnum string) error
	IscsiFormatVolume(ctx context.Context, serialnum, fslabel string) error

	IscsiVolumeMount(fslabel string, path string) error
	IscsiVolumeUnmount(fslabel string, path string) error
	IscsiGetVolumeMounts(fslabel string, filter bool) ([]string, error)

	IscsiSetMutualChapSecret(ctx context.Context, req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error)
}

var errStubImpl = fmt.Errorf("stubhandler not implemented")

type stubIscsiMounter struct {
}

func (m *stubIscsiMounter) IscsiAddTargetPortal(ctx context.Context, addr string, port uint32) error {
	return errStubImpl
}
func (m *stubIscsiMounter) IscsiConnectTargetNoAuth(ctx context.Context, addr string, port uint32, iqn string) error {
	return errStubImpl
}
func (m *stubIscsiMounter) IscsiDisconnectTarget(ctx context.Context, iqn string) error {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiDiscoverTargetPortal(ctx context.Context, addr string, port uint32) ([]string, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiListTargetPortals(ctx context.Context) ([]iscsi.TargetPortal, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiRemoveTargetPortal(ctx context.Context, addr string, port uint32) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeExists(ctx context.Context, fsLabel string) (bool, error) {
	return false, errStubImpl
}

func (m *stubIscsiMounter) IscsiDiskInitialized(ctx context.Context, serialnum string) (bool, error) {
	return false, errStubImpl
}

func (m *stubIscsiMounter) IscsiDiskInit(ctx context.Context, serialnum string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiFormatVolume(ctx context.Context, serialnum string, fslabel string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeMount(fslabel string, path string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeUnmount(fslabel string, path string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiGetVolumeMounts(fslabel string, filter bool) ([]string, error) {
	return nil, errStubImpl
}

func (m *stubIscsiMounter) IscsiSetMutualChapSecret(ctx context.Context, req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error) {
	return nil, errStubImpl
}
