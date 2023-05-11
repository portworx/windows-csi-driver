package mounter

import (
	"fmt"
)

const pwxtag = "Portworx Network Drive"
const workDir = "C:\\pwxvol"

func volumePath(volid string) string {
	return fmt.Sprintf("%s\\%s", workDir, volid)
}

type DriveInfoObj struct {
	CurrentLocation string // not sure what is this
	Name string // drive name: should match volume id
	Root string // UNC path //<ip>/share/path
	Used uint64 // Need to check if used works
	Description string // should match 'pwxtag'
}

type NfsMounter interface {
	NfsMount(source, target, fsType string, mountOptions, sensitiveMountOptions []string) error
	NfsUnmount(target string) error

	AddDrive(volid string, share_path string, sensitiveMountOptions []string) error
	RmDrive(volid string) error
	DriveInfo(volid string) (*DriveInfoObj, bool, error)
	DriveExists(volid string) (bool, error)
	MkLink(volid, target string) error
	RmLink(volid, target string) error
	MkVolume(volid string) error
	RmVolume(volid string) error
}

type stubNfsMounter struct {}

func (nfs *stubNfsMounter) AddDrive(
	volid string,
	share_path string,
	sensitiveMountOptions []string,
) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) RmDrive(
	volid string,
) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) DriveInfo(
	volid string,
) (*DriveInfoObj, bool, error) {
	return nil, false, errStubImpl
}

func (nfs *stubNfsMounter) DriveExists(
	volid string,
) (bool, error) {
	return false, errStubImpl
}

func (nfs *stubNfsMounter) MkVolume(volid string) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) MkLink(volid, target string) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) RmLink(volid, target string) error {
	return errStubImpl
}


func (nfs *stubNfsMounter) RmVolume(volid string) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) NfsMount(
	source, target, fstype string,
	mountOptions, sensitiveMountOptions []string,
) error {
	return errStubImpl
}


func (nfs *stubNfsMounter) NfsUnmount(target string) error {
	return errStubImpl
}
