package mounter

import (
	"fmt"
)

const pwxtag = "Portworx Network Drive"
const workDir = "C:\\var\\pxvol"
const mountDir = "C:\\var\\pxd.portworx.com\\mounts"
const mountInfoDir = "C:\\var\\pxd.portworx.com\\mountInfo"

func getMountPath(volid, uuid string) string {
	return fmt.Sprintf("%s\\%s_%s", mountDir, volid, uuid)
}

func getMountInfoPath(volid, uuid string) string {
	return fmt.Sprintf("%s\\%s_%s", mountInfoDir, volid, uuid)
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
	NfsMount(source, target, fsType, endpoint, podID, podName, podNamespace string, mountOptions, sensitiveMountOptions []string) error
	NfsUnmount(volumeId string, target string) error
	AddDrive(volid string, sharePath string, sensitiveMountOptins []string, csimode string, uuidPath string, uuid string) error
	RmDrive(volid string, targetPath string) error
	DriveExists(volid string) (bool, error)
	MkLink(volid, target string) error
	RmLink(volid, target string) error
	CheckVolidMounted(volid string) bool
	BackGroundMountProcess(ipAddr string)
	ReadSavedData(volid, targetPath string) (string, string, string, string, string, error)
}

type stubNfsMounter struct{}

func (nfs *stubNfsMounter) AddDrive(
	volid string,
	share_path string,
	sensitiveMountOptions []string,
	csimode string,
	uuidPath string,
	uuid string,
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
	endpoint, podID, podName, podNameSpace string,
	mountOptions, sensitiveMountOptions []string,
) error {
	return errStubImpl
}

func (nfs *stubNfsMounter) NfsUnmount(volumeId string, target string) error {
	return errStubImpl
}
