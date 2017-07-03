// goal is for us to test all the functions that are being called
//probably mock responses from the Docker API to not have to test with a real daemon

package actuary


import (
	"os"
	"path/filepath"
	"fmt"
	"encoding/json"
	"testing"
	"strconv"
	"net/http" //Package http provides HTTP client and server implementations.
	"net/http/httptest" //Package httptest provides utilities for HTTP testing.
	"github.com/docker/engine-api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/api"
)

//variables for tests, helper functions
//Rest of test files use the following functions/variables!

//group together the api call and the expected object (in bytes)
type callPairing struct{
	call string
	obj []byte
}

type imageList struct{
	images []types.Image
}

type typeContainerList struct{
	typeContainers []types.Container
}

//For testing functions that require a specific number of images
func (list imageList) populateImageList(size int) (imageList){
	list.images = nil
	var img types.Image
	for i := 0; i < size; i++{
		img = types.Image{ID: strconv.Itoa(i)}
		list.images = append(list.images, img)
	}

	return list
}

//For testing functions that require a specific number of containers
func (list typeContainerList) populateContainerList(size int) (typeContainerList){
	list.typeContainers = nil
	var c types.Container
	for i := 0; i < size; i++{
		c = types.Container{ID: strconv.Itoa(i)}
		list.typeContainers = append(list.typeContainers, c)
	}

	return list
}

var testTarget, err = NewTarget()

func testServer (t *testing.T, pairings ...callPairing) (server *httptest.Server) { //inject a different response based on the test
//"pairings" used because there is sometimes more than one call to be mocked for a function
	mux := http.NewServeMux()

	for _, pair := range pairings {
		mux.HandleFunc(
			fmt.Sprintf("/v1.26%s", pair.call),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
				w.Header().Set("Content-Type", "application/json")
				w.Write(pair.obj)
		}))
	}

	server = httptest.NewServer(mux)

	//manipulate testTarget client to point to server
	testTarget.Client, err = client.NewClient(server.URL, api.DefaultVersion, nil, nil)

	if err != nil {
		t.Errorf("Could not manipulate test target client.")
		return 
	}
	return 
}

//1. host configuration
//Mainly system file calls
//Method here: redirect what files the functions are run on -- files created in the /testdata folder. 
//Do this through the use of global variables, make sure to restore original values

func TestCheckSeparatePartition(t *testing.T){
	temp := fstab
	fstab = "testdata/fstabPass" //redefine the global variable

	for i := 0; i< 2; i++{
		res := CheckSeparatePartition(testTarget)

		if  i == 0 && res.Status != "PASS" {
			t.Errorf("Fstab set to contain /var/lib/docker, should have passed" )
		}

		if  i == 1 && res.Status == "PASS" {
			t.Errorf("Fstab does not contain /var/lib/docker, should not have passed" )
		}

		//fail case

		fstab = "testdata/fstabFail"
	}
	
	//restore

	fstab = temp
}

func TestCheckKernelVersion(t *testing.T) {
	//just checks info.KernelVersion of target. Fake info within testTarget
	t.Log("Changing Kernel Version to 4.9.27-moby")

	testTarget.Info.KernelVersion = "4.9.27-moby"

	res := CheckKernelVersion(testTarget)
	if  res.Status != "PASS" {
		t.Errorf("Kernel Version is correct, should have passed." )
	}

	testTarget.Info.KernelVersion = "1.9.27-moby"

	res = CheckKernelVersion(testTarget)
	if  res.Status == "PASS" {
		t.Errorf("Kernel Version is incorrect, should not have passed." )
	}
}

func TestCheckRunningServices(t *testing.T) {
	//not mac compatible
}

func TestCheckDockerVersion(t *testing.T) {
	//mock server required
	
	var ver = types.Version{
		Version: "20000",
		Os: "linux",
		GoVersion: "go1.7.5",
		GitCommit: "deadbee",
	}

	for i := 0; i< 2; i++{
		vJSON, err := json.Marshal(ver)

		if err != nil {
			t.Errorf("Could not convert version to json.")
		}

		p := callPairing{"/version", vJSON}

		ts := testServer(t, p)
		
		res := CheckDockerVersion(testTarget)

		defer ts.Close()

		if i == 0 && res.Status != "PASS" {
			t.Errorf("Host using the correct Docker server, should pass" )
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf("Host not using the correct Docker server, should not pass" )
		}

		//fail case

		ver.Version = "0"
	}

 }

func TestCheckTrustedUsers(t *testing.T) {
	temp := groupFile
	groupFile = "testData/groupPass"

	for i := 0; i< 2; i++{
	
		res := CheckTrustedUsers(testTarget)
		
		if  i == 0 && res.Output != "The following users control the Docker daemon: [user1 user2 user3]"{
				t.Errorf("Group file set to have two users (user1, user2, user3), should have passed" )
		}

		if  i == 1 && res.Output != "The following users control the Docker daemon: []"{
				t.Errorf("Group file has no users." )
		}

		groupFile = "testData/groupFail"
	}
	
	//fail case and restoration

	groupFile = temp
}

//if these tests don't run right, make sure the executable bit is set on the binary test files in testdata
func changePath(t *testing.T, binLoc string) {
	//This function is necessary in running all of the tests that check system files
	// get the absolute location of the directory your test binary
	// your test binary should be at testdata/testauditctl1/auditctl
	// make sure the executable bit is set on that file (chmod +x)
	binlocation, err := filepath.Abs(binLoc)
	if err != nil {
	    t.Errorf("Could not retrieve location of test binary.")
	}
	// get the current path
	path := os.Getenv("PATH")

	// add the test binary directory to the beginning so its searched first
	// no cleanup is necessary; this change to PATH only exists for the lifetime
	// of your process. this change to PATH with persist even in other tests!
	err = os.Setenv("PATH", binlocation + ":" + path)
	if err != nil {
	    t.Errorf("Could not set filepath to test binary")
	}

	//log.Printf("New path: %v", os.Getenv("PATH"))
	// now if you do this, the binary with the same name in your 
	// testdata/testbinaries directory will be the fake binary you created
	//bin, err := exec.LookPath("auditctl")
	//log.Printf("BIN %v", bin)
	// now bin == /whatever/whatever/testdata/testauditclt1/auditctl
}

func TestAuditDockerDaemon(t *testing.T) {
	
	changePath(t, "testdata/auditctl1")

	res := AuditDockerDaemon(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of docker daemon should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditDockerDaemon(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of docker daemon should not pass." )
	}
}

func TestAuditLibDocker(t *testing.T) {
	changePath(t, "testdata/auditctl1")

	res := AuditLibDocker(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /var/lib/docker should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditLibDocker(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /var/lib/docker should not pass." )
	}	
}

func TestAuditEtcDocker(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditEtcDocker(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /etc/docker should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditEtcDocker(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /etc/docker should not pass." )
	}	
}

func TestAuditDockerService(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditDockerService(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /usr/lib/systemd/system/docker.service should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditDockerService(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /usr/lib/systemd/system/docker.service should not pass." )
	}	
}
func TestAuditDockerSocket(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditDockerSocket(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /usr/lib/systemd/system/docker.socket should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditDockerSocket(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /usr/lib/systemd/system/docker.socket should not pass." )
	}	
}

func TestAuditDockerDefault(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditDockerDefault(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /etc/default/docker should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditDockerDefault(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /etc/default/docker should not pass." )
	}	
}

func TestAuditDaemonJSON(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditDaemonJSON(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /etc/docker/daemon.json should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditDaemonJSON(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /etc/docker/daemon.json should not pass." )
	}	
}

func TestAuditContainerd(t *testing.T)  {
	changePath(t, "testdata/auditctl1")

	res := AuditContainerd(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /usr/bin/docker-containerd should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditContainerd(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /usr/bin/docker-containerd should not pass." )
	}	
}
func TestAuditRunc(t *testing.T) {
	changePath(t, "testdata/auditctl1")

	res := AuditRunc(testTarget)

	if res.Status != "PASS"{
			t.Errorf("Audit of /usr/bin/docker-runc should pass." )
	}

	//test fail case

	changePath(t, "testdata/auditctl2")

	res = AuditRunc(testTarget)

	if res.Status == "PASS"{
			t.Errorf("Audit of /usr/bin/docker-runc should not pass." )
	}	
}