//go:build windows
// +build windows

package mounter

import (
	"bytes"
	"os"
	"os/exec"

	"k8s.io/klog/v2"
)

const MaxPathLengthWindows = 260

// returns: stdout, stderr, err
func RunPowershellCmd(command string, envs ...string) ([]byte, []byte, error) {
	// not able to find powershell from within container. some have pwsh.exe. Path issue?
	cmd := exec.Command("powershell", "-Mta", "-NoProfile", "-Command", command)
	cmd.Env = append(os.Environ(), envs...)
	klog.V(8).Infof("Executing command: %q", cmd.String())

	var sout, serr bytes.Buffer

	cmd.Stdout = &sout
	cmd.Stderr = &serr

	err := cmd.Run()
	return sout.Bytes(), serr.Bytes(), err
}

// returns: stdout, stderr, err
func RunCmd(command string, envs ...string) ([]byte, []byte, error) {
	cmd := exec.Command("cmd.exe", "/c", command)
	cmd.Env = append(os.Environ(), envs...)
	klog.V(8).Infof("Executing command: %q", cmd.String())

	var sout, serr bytes.Buffer

	cmd.Stdout = &sout
	cmd.Stderr = &serr

	err := cmd.Run()
	return sout.Bytes(), serr.Bytes(), err
}
