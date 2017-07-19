package actuary

import (
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"          //Package http provides HTTP client and server implementations.
	"net/http/httptest" //Package httptest provides utilities for HTTP testing.
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// variables for tests, helper functions
// Rest of test files use the following functions/variables
type callPairing struct {
	call string
	obj  []byte
}

type imageList struct {
	images []types.ImageSummary
}

type typeContainerList struct {
	typeContainers []types.Container
}

// For testing functions that require a specific number of images
func (list imageList) populateImageList(size int) imageList {
	list.images = nil
	var img types.ImageSummary
	for i := 0; i < size; i++ {
		img = types.ImageSummary{ID: strconv.Itoa(i)}
		list.images = append(list.images, img)
	}
	return list
}

// For testing functions that require a specific number of containers
func (list typeContainerList) populateContainerList(size int) typeContainerList {
	list.typeContainers = nil
	var c types.Container
	for i := 0; i < size; i++ {
		c = types.Container{ID: strconv.Itoa(i)}
		list.typeContainers = append(list.typeContainers, c)
	}
	return list
}

func NewTestTarget(proc []string) (*Target, error) {
	target := &Target{
		Info:       types.Info{},
		Containers: ContainerList{Container{ID: "Container_id1", Info: ContainerInfo{}}},
	}

	target.ProcFunc = func(procname string) (cmd []string, err error) {
		err = nil
		cmd = proc
		return
	}
	target.CertPath = func(procname string, tlsOpt string) (val string) {
		val = "/etc/docker"
		return
	}

	return target, nil
}

func (target *Target) testServer(t *testing.T, pairings ...callPairing) (server *httptest.Server) {
	var err error
	mux := http.NewServeMux()
	for _, pair := range pairings {
		mux.HandleFunc(
			fmt.Sprintf("/v1.31%s", pair.call),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				param := r.URL.Query()["all"]
				if pair.call == "/container" {
					if len(param) > 0 {
						w.Write(pairings[1].obj)
					} else {
						w.Write(pairings[0].obj)
					}
				} else {
					w.Write(pair.obj)
				}
			}))
	}
	server = httptest.NewServer(mux)
	// Manipulate testTarget client to point to server
	target.Client, err = client.NewClient(server.URL, api.DefaultVersion, nil, nil)
	if err != nil {
		t.Errorf("Could not manipulate test target client.")
	}
	return
}

// 1. host configuration
func TestCheckSeparatePartitionSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	content := []byte("/filler /var/lib/docker")
	dir, err := ioutil.TempDir("testdata/etc/", "fstab")
	if err != nil {
		t.Errorf("Could not create temporary directory")
	}
	defer os.RemoveAll(dir)
	testTarget.BaseDir = "testdata"
	err = ioutil.WriteFile("testdata/etc/fstab", content, 0666)
	defer os.Remove("testdata/etc/fstab")
	if err != nil {
		t.Errorf("Could not write temp file: %s", err)
	}
	res := CheckSeparatePartition(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Fstab set to contain /var/lib/docker, should have passed")
}

func TestCheckSeparatePartitionFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	content := []byte("/filler /wrong")
	dir, err := ioutil.TempDir("testdata/etc", "fstab")
	if err != nil {
		t.Errorf("Could not create temporary directory")
	}
	defer os.RemoveAll(dir)
	testTarget.BaseDir = "testdata"
	err = ioutil.WriteFile("testdata/etc/fstab", content, 0666)
	defer os.Remove("testdata/etc/fstab")
	if err != nil {
		t.Errorf("Could not write temp file: %s", err)
	}
	res := CheckSeparatePartition(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Fstab does not contain /var/lib/docker, should not have passed")
}

// Checks info.KernelVersion of target. Fake info within testTarget
func TestCheckKernelVersionSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	testTarget.Info.KernelVersion = "4.9.27-moby"
	res := CheckKernelVersion(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Kernel Version is correct, should have passed.")
}

func TestCheckKernelVersionFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	testTarget.Info.KernelVersion = "1.9.27-moby"
	res := CheckKernelVersion(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Kernel Version is incorrect, should not have passed.")
}

func TestCheckRunningServicesSuccess(t *testing.T) {
	// testTarget, err := NewTestTarget([]string{""})
	// if err != nil {
	// 	t.Errorf("Could not create testTarget")
	// }
	// temp := tcpData
	// p := GOnetstat.Process{Port: int64(2.0)}
	// tcpData = []GOnetstat.Process{p}
	// res := CheckRunningServices(*testTarget)
	// assert.Equal(t, "Host listening on 1 ports: 1", res.Output, "One open port")
	// // Restore
	// tcpData = temp
}

func TestCheckDockerVersionSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var ver = types.Version{
		Version:   "20000",
		Os:        "linux",
		GoVersion: "go1.7.5",
		GitCommit: "deadbee",
	}
	vJSON, err := json.Marshal(ver)
	if err != nil {
		t.Errorf("Could not convert version to json.")
	}
	p := callPairing{"/version", vJSON}
	ts := testTarget.testServer(t, p)
	res := CheckDockerVersion(*testTarget)
	defer ts.Close()
	assert.Equal(t, "PASS", res.Status, "Host using the correct Docker server, should pass")
}

func TestCheckDockerVersionFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var ver = types.Version{
		Version:   "0",
		Os:        "linux",
		GoVersion: "go1.7.5",
		GitCommit: "deadbee",
	}
	vJSON, err := json.Marshal(ver)
	if err != nil {
		t.Errorf("Could not convert version to json.")
	}
	p := callPairing{"/version", vJSON}
	ts := testTarget.testServer(t, p)
	res := CheckDockerVersion(*testTarget)
	defer ts.Close()
	assert.Equal(t, "WARN", res.Status, "Host not using the correct Docker server, should not pass")
}

func TestCheckTrustedUsersSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	content := []byte("docker:users: user1, user2, user3")
	dir, err := ioutil.TempDir("testdata/etc", "group")
	if err != nil {
		t.Errorf("Could not create temporary directory")
	}
	defer os.RemoveAll(dir)
	testTarget.BaseDir = "testdata"
	err = ioutil.WriteFile("testdata/etc/group", content, 0666)
	defer os.Remove("testdata/etc/group")
	if err != nil {
		t.Errorf("Could not write temp file: %s", err)
	}
	res := CheckTrustedUsers(*testTarget)
	assert.Equal(t, "The following users control the Docker daemon: [user1 user2 user3]", res.Output, "Group file set to have two users (user1, user2, user3), should have passed")
}

func TestCheckTrustedUsersFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	content := []byte("docker:users:")
	dir, err := ioutil.TempDir("testdata/etc", "groupFile")
	defer os.Remove("testdata/etc/fstab")
	if err != nil {
		t.Errorf("Could not create temporary directory")
	}
	defer os.RemoveAll(dir)
	testTarget.BaseDir = "testdata"
	err = ioutil.WriteFile("testdata/etc/group", content, 0666)
	defer os.Remove("testdata/etc/group")
	if err != nil {
		t.Errorf("Could not write temp file: %s", err)
	}
	res := CheckTrustedUsers(*testTarget)
	assert.Equal(t, "The following users control the Docker daemon: []", res.Output, "Group file has no users.")
}

// This function is necessary in running all of the tests that check system files
// Get the absolute location of the directory your test binary
// Your test binary should be at testdata/testauditctl1/auditctl
// Make sure the executable bit is set on that file (chmod +x)
// If these tests don't run right, make sure the executable bit is set on the binary test files in testdata
func changePath(t *testing.T, binLoc string) {
	binlocation, err := filepath.Abs(binLoc)
	if err != nil {
		t.Errorf("Could not retrieve location of test binary.")
	}
	// get the current path
	path := os.Getenv("PATH")
	// add the test binary directory to the beginning so its searched first
	// no cleanup is necessary; this change to PATH only exists for the lifetime
	// of your process. this change to PATH with persist even in other tests!
	err = os.Setenv("PATH", binlocation+":"+path)
	if err != nil {
		t.Errorf("Could not set filepath to test binary")
	}
}

func TestAuditDockerDaemonSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/usr/bin/docker\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerDaemon(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of docker daemon should pass.")
}

func TestAuditDockerDaemonFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerDaemon(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of docker daemon should not pass.")
}

func TestAuditLibDockerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/var/lib/docker\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	//defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditLibDocker(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /var/lib/docker should pass.")
}

func TestAuditLibDockerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditLibDocker(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /var/lib/docker should not pass.")
}

func TestAuditEtcDockerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/etc/docker\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditEtcDocker(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /etc/docker should pass.")
}

func TestAuditEtcDockerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditEtcDocker(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /etc/docker should not pass.")
}

func TestAuditDockerServiceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/usr/lib/systemd/system/docker.service\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerService(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /usr/lib/systemd/system/docker.service should pass.")
}

func TestAuditDockerServiceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerService(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /usr/lib/systemd/system/docker.service should not pass.")
}

func TestAuditDockerSocketSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/usr/lib/systemd/system/docker.socket\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerSocket(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /usr/lib/systemd/system/docker.socket should pass.")
}

func TestAuditDockerSocketFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerSocket(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /usr/lib/systemd/system/docker.socket should not pass.")
}

func TestAuditDockerDefaultSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/etc/default/docker\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerDefault(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /etc/default/docker should pass.")
}

func TestAuditDockerDefaultFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDockerDefault(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /etc/default/docker should not pass.")
}

func TestAuditDaemonJSONSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/etc/docker/daemon.json\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDaemonJSON(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /etc/docker/daemon.json should pass.")
}

func TestAuditDaemonJSONFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditDaemonJSON(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /etc/docker/daemon.json should not pass.")
}

func TestAuditContainerdSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/usr/bin/docker-containerd\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditContainerd(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /usr/bin/docker-containerd should pass.")
}

func TestAuditContainerdFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditContainerd(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /usr/bin/docker-containerd should not pass.")
}

func TestAuditRuncSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"/usr/bin/docker-runc\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditRunc(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Audit of /usr/bin/docker-runc should pass.")
}

func TestAuditRuncFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget: %s", err)
	}
	content := []byte("#!/bin/bash \n echo \"failing data\"")
	err = ioutil.WriteFile("testdata/auditctl", content, 0700)
	if err != nil {
		t.Errorf("Could not write temporary file %s", err)
	}
	defer os.Remove("testdata/auditctl")
	changePath(t, "testdata/")
	res := AuditRunc(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Audit of /usr/bin/docker-runc should not pass.")
}
