package mounter

import (
	"context"
	"fmt"

	iscsi "github.com/kubernetes-csi/csi-proxy/client/api/iscsi/v1alpha2"
)



type IscsiMounter interface {
	///  Iscsi specifics
	IscsiAddTargetPortal(ctx context.Context, req *iscsi.AddTargetPortalRequest) (*iscsi.AddTargetPortalResponse, error)
	IscsiConnectTarget(ctx context.Context, req *iscsi.ConnectTargetRequest) (*iscsi.ConnectTargetResponse, error)
	IscsiDisconnectTarget(ctx context.Context, req *iscsi.DisconnectTargetRequest) (*iscsi.DisconnectTargetResponse, error)
	IscsiDiscoverTargetPortal(ctx context.Context, req *iscsi.DiscoverTargetPortalRequest) (*iscsi.DiscoverTargetPortalResponse, error)
	IscsiGetTargetDisks(ctx context.Context, req *iscsi.GetTargetDisksRequest) (*iscsi.GetTargetDisksResponse, error)
	IscsiListTargetPortals(ctx context.Context, req *iscsi.ListTargetPortalsRequest) (*iscsi.ListTargetPortalsResponse, error)
	IscsiRemoveTargetPortal(ctx context.Context, req *iscsi.RemoveTargetPortalRequest) (*iscsi.RemoveTargetPortalResponse, error)
	IscsiSetMutualChapSecret(ctx context.Context, req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error)
}

var errStubImpl = fmt.Errorf("stubhandler not implemented")

type stubIscsiMounter struct {
}

func (m *stubIscsiMounter) IscsiAddTargetPortal(ctx context.Context, req *iscsi.AddTargetPortalRequest) (*iscsi.AddTargetPortalResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiConnectTarget(ctx context.Context, req *iscsi.ConnectTargetRequest) (*iscsi.ConnectTargetResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiDisconnectTarget(ctx context.Context, req *iscsi.DisconnectTargetRequest) (*iscsi.DisconnectTargetResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiDiscoverTargetPortal(ctx context.Context, req *iscsi.DiscoverTargetPortalRequest) (*iscsi.DiscoverTargetPortalResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiGetTargetDisks(ctx context.Context, req *iscsi.GetTargetDisksRequest) (*iscsi.GetTargetDisksResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiListTargetPortals(ctx context.Context, req *iscsi.ListTargetPortalsRequest) (*iscsi.ListTargetPortalsResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiRemoveTargetPortal(ctx context.Context, req *iscsi.RemoveTargetPortalRequest) (*iscsi.RemoveTargetPortalResponse, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiSetMutualChapSecret(ctx context.Context, req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error) {
	return nil, errStubImpl
}

