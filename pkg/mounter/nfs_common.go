package mounter

import (
	"fmt"
)

const pwxtag = "Portworx Network Drive"
const workDir = "C:\\var\\pxvol"

func volumePath(volid string) string {
	return fmt.Sprintf("%s\\%s", workDir, volid)
}

func credFile() string {
	return fmt.Sprintf("%s\\%s", workDir, "credential.txt")
}

type DriveInfoObj struct {
	CurrentLocation string
	Name            string //Drive Name: volid.
	Root            string //UNC path //<ip>/sharepath
	Used            int64
	Description     string //tagged with pwxtag
}

type NfsMounter interface {
	NfsMount(source, target, fsType string, mountOptions, sensitiveMountOptions []string) error
	NfsUnmount(volumeId string, target string) error
	AddDrive(volid string, sharePath string, sensitiveMountOptins []string, csimode string) error
	RmDrive(volid string, targetPath string) error
	DriveExists(volid string) (bool, error)
	MkLink(volid, target string) error
	RmLink(volid, target string) error
	CheckVolidMounted(volid string) bool
}

type stubNfsMounter struct{}

func (nfs *stubNfsMounter) AddDrive(
	volid string,
	share_path string,
	sensitiveMountOptions []string,
	csimode string,
) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) RmDrive(
	volid string,
	path string,
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

func (nfs *stubNfsMounter) NfsUnmount(volumeId string, target string) error {
	return errStubImpl
}
