package actuary

import (
	"github.com/stretchr/testify/assert"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// 3. Docker daemon configuration files
// For the functions that use systemdPaths, change the global variable to point to the testdata folder
func changeSystemDPath(t *testing.T) {
	path, err := filepath.Abs("testdata")
	if err != nil {
		t.Errorf("Could not get current user information %s", err)
	}
	systemdPaths = []string{path}
}

// Covers all functions that involve checking the file's owner.
// Sets the root user to be the test file's current user for the pass test case and to be the root on the fail case.
// Did it this way because could not make the test files created be "owned" by root
// Potential problem: If the test files' owner is actually root -- is this possible with this setup?
func checkOwnerSuccess(t *testing.T, target Target, f func(tg Target) Result, gid bool) (res Result) {
	usr, err := user.Current() // Change root user to current user for positive test case
	refUser = usr.Name
	// Only some of the functions test the gid, additional test signified by bool input
	if gid {
		gid, err := user.LookupGroupId(usr.Gid)
		refGroup = gid.Name
		if err != nil {
			t.Errorf("Could not get gid: %s", err)
		}
	}
	if err != nil {
		t.Errorf("Could not get current user information %s", err)
	}
	res = f(target)
	//restore?
	return
}

func checkOwnerFail(t *testing.T, target Target, f func(tg Target) Result, gid bool) (res Result) {
	refUser = "root"
	if gid {
		refGroup = "root"
	}
	res = f(target)
	return
}

// Covers all functions that involve checking the file's permissions
// Sets the reference permissions in the original functions to the test files' permissions for the pass case
// Same potential problem as above
func checkPermsSuccess(t *testing.T, target Target, fi os.FileInfo, f func(tg Target) Result) (res Result) {
	mode := fi.Mode().Perm()
	refPerms = uint32(mode)
	res = f(target)
	return
}

func checkPermsFail(t *testing.T, target Target, fi os.FileInfo, f func(tg Target) Result) (res Result) {
	mode := fi.Mode().Perm()
	refPerms = uint32(mode) - 1
	res = f(target)
	return
}

func TestCheckServiceOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	res := checkOwnerSuccess(t, *testTarget, CheckServiceOwner, false)
	assert.Equal(t, "PASS", res.Status, "Root set to docker.service owner, should pass")
}

func TestCheckServiceOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	res := checkOwnerFail(t, *testTarget, CheckServiceOwner, false)
	assert.Equal(t, "WARN", res.Status, "Docker.service owner is not set to root, should not pass.")
}

func TestCheckServicePermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	fileInfo, err := lookupFile("docker.service", systemdPaths)
	if err != nil {
		t.Errorf("Could not lookup file docker.service: %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckServicePerms)
	assert.Equal(t, "PASS", res.Status, "Docker.service permissions set, should pass.")
	// Restore
	refPerms = 0644
}

func TestCheckServicePermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	fileInfo, err := lookupFile("docker.service", systemdPaths)
	if err != nil {
		t.Errorf("Could not lookup file docker.service: %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckServicePerms)
	assert.Equal(t, "WARN", res.Status, "Docker.service permissions not set, should not pass.")
	// Restore
	refPerms = 0644
}

func TestCheckSocketOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	res := checkOwnerSuccess(t, *testTarget, CheckSocketOwner, false)
	assert.Equal(t, "PASS", res.Status, "Root set to docker.socket owner, should pass")
}

func TestCheckSocketOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	res := checkOwnerFail(t, *testTarget, CheckSocketOwner, false)
	assert.Equal(t, "WARN", res.Status, "Docker.socket owner not set, should not pass.")
}

func TestCheckSocketPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	fileInfo, err := lookupFile("docker.socket", systemdPaths)
	if err != nil {
		t.Errorf("Could not get docker.socket file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckSocketPerms)
	assert.Equal(t, "PASS", res.Status, "Docker.socket permissions set, should pass.")
	// Restore
	refPerms = 0644
}

func TestCheckSocketPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	changeSystemDPath(t)
	fileInfo, err := lookupFile("docker.socket", systemdPaths)
	if err != nil {
		t.Errorf("Could not get docker.socket file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckSocketPerms)
	assert.Equal(t, "WARN", res.Status, "Docker.socket permissions not set, should not pass.")
	// Restore
	refPerms = 0644
}

func TestCheckDockerDirOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckDockerDirOwner, false)
	assert.Equal(t, "PASS", res.Status, "Root set to /etc/docker directory ownership, should pass")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckDockerDirOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckDockerDirOwner, false)
	assert.Equal(t, "WARN", res.Status, "/etc/docker directory ownership != root, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckDockerDirPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get /etc/docker file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckDockerDirPerms)
	assert.Equal(t, "PASS", res.Status, "/etc/docker permissions set, should pass.")
	// Restore
	refPerms = 0755
	etcDocker = "etc/Docker"
}

func TestCheckDockerDirPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get /etc/docker file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckDockerDirPerms)
	assert.Equal(t, "WARN", res.Status, "/etc/docker permissions not set, should not pass.")
	// Restore
	refPerms = 0755
	etcDocker = "etc/Docker"
}

func TestCheckRegistryCertOwner(t *testing.T) {

	// Original function .ReadDir called on a relative path, seems wrong...

	// loc, err := filepath.Abs("testdata/etc/docker/certs.d/certFolder")
	// path := os.Getenv("PATH")
	// err = os.Setenv("PATH", loc + ":" + path)

	// rootPath, _ := os.Getwd()
	// etcDockerCert = filepath.Join(rootPath, "/testdata/etc/docker/certs.d")

	// files, err := ioutil.ReadDir(etcDockerCert)

	// for _, file := range files {
	// 	if file.IsDir() {
	// 		certs, err := ioutil.ReadDir(file.Name())
	// 		log.Printf("FILE: %v", file)
	// 		log.Printf("Err: %v", err)

	// 		for _, cert := range certs {
	// 			log.Printf("CERT: %v", cert.Name())
	// 		}
	// 	}
	// }

	// //path := filepath.Join(etcDockerCert, "certFolder")

	// //certs, err := ioutil.ReadDir(path)

	// usr, err := user.Current() // change root user to current user for positive test case
	// refUser = usr.Name

	// if err != nil {
	// 	t.Errorf("Could not get current user information %s", err)
	// }

	// res := CheckRegistryCertOwner(*testTarget)

	// assert.Equal(t, "PASS", res.Status,  {
	// 		t.Errorf("Root set to /etc/docker directory ownership, should pass" )
	// }

	// refUser = "root"

	// res = CheckRegistryCertOwner(*testTarget)

	// assert.Equal(t, "WARN", res.Status,
	// 		t.Errorf("/etc/docker directory ownership != root, should not pass." )
	// }

	// //restore
	// etcDockerCert = "etc/Docker/certs.d"

}

func TestCheckRegistryCertPerms(t *testing.T) {
	// Same problem as above
}

// Following 7 tests are combinations of tests from dockerconf_test.go and other test functions within dockerfiles_test.go
// Insert dummy test file by replacing call to procSetUp
// PROBLEM: Using a file created and placed in an arbitrary folder (etcDocker)
// because could not find the expected certPath value (nil currently). Shouldn't matter, but not ideal.
func TestCheckCACertOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckCACertOwner, false)
	assert.Equal(t, "PASS", res.Status, "Root:root is set to TLS CA certificate file ownership, should pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckCACertOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckCACertOwner, false)
	assert.Equal(t, "WARN", res.Status, "Root:root is not set to TLS CA certificate file ownership, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckCACertPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckCACertPerms)
	assert.Equal(t, "PASS", res.Status, "TLS CA certificate file permissions are set correctly, should pass")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckCACertPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckCACertPerms)
	assert.Equal(t, "WARN", res.Status, "File has less restrictive permissions than expected, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckServerCertOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckServerCertOwner, false)
	assert.Equal(t, "PASS", res.Status, "Root:root is set to Docker server certificate file ownership, should pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckServerCertOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckServerCertOwner, false)
	assert.Equal(t, "WARN", res.Status, "Root:root is not set to Docker server certificate file ownership, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckServerCertPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckServerCertPerms)
	assert.Equal(t, "PASS", res.Status, "Docker server certificate file permissions are set, should pass")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckServerCertPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckServerCertPerms)
	assert.Equal(t, "WARN", res.Status, "Docker server certificate file permissions are not set, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckCertKeyOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckCertKeyOwner, true)
	assert.Equal(t, "PASS", res.Status, "Root:root is set to Docker server certificate key file ownership, should pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckCertKeyOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckCertKeyOwner, true)
	assert.Equal(t, "WARN", res.Status, "Root:root is not set to Docker server certificate key file ownership, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
}

func TestCheckCertKeyPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckCertKeyPerms)
	assert.Equal(t, "PASS", res.Status, "Docker server certificate key file permissions are set, should pass")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0400
}

func TestCheckCertKeyPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	}
	fileInfo, err := os.Stat(etcDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckCertKeyPerms)
	assert.Equal(t, "WARN", res.Status, "Docker server certificate key file permissions are not set, should not pass.")
	// Restore
	etcDocker = "etc/Docker"
	refPerms = 0400
}

func TestCheckDockerSockOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckDockerSockOwner, true)
	assert.Equal(t, "PASS", res.Status, "Docker socket file ownership is set to root:docker, should pass")
	// Restore
	varRunDockerSock = "/var/run/docker.sock"
	refGroup = "docker"
}

func TestCheckDockerSockOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckDockerSockOwner, true)
	assert.Equal(t, "WARN", res.Status, "Docker socket file ownership is not set to root:docker, should not pass.")
	// Restore
	varRunDockerSock = "/var/run/docker.sock"
	refGroup = "docker"
}

func TestCheckDockerSockPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	}
	fileInfo, err := os.Stat(varRunDockerSock)
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckDockerSockPerms)
	assert.Equal(t, "PASS", res.Status, "Docker sock file permissions are set, should pass")
	// Restore
	varRunDockerSock = "/var/run/docker.sock"
}

func TestCheckDockerSockPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	}
	fileInfo, err := os.Stat(varRunDockerSock)
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckDockerSockPerms)
	assert.Equal(t, "WARN", res.Status, "Docker sock file permissions are not set, should not pass.")
	// Restore
	varRunDockerSock = "/var/run/docker.sock"
}

func TestCheckDaemonJSONOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckDaemonJSONOwner, true)
	assert.Equal(t, "PASS", res.Status, "Root:root ownership is set to Daemon.json file's owner, should pass")
	// Restore
	etcDockerDaemon = "/etc/docker/daemon.json"
	refGroup = "root"
}

func TestCheckDaemonJSONOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckDaemonJSONOwner, true)
	assert.Equal(t, "WARN", res.Status, "Root:root ownership is not set to Daemon.json file's owner, should not pass.")
	// Restore
	etcDockerDaemon = "/etc/docker/daemon.json"
	refGroup = "root"
}

func TestCheckDaemonJSONPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	}
	fileInfo, err := os.Stat(etcDockerDaemon)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckDaemonJSONPerms)
	assert.Equal(t, "PASS", res.Status, "Daemon.json file permissions are set, should pass.")
	// Restore
	etcDockerDaemon = "/etc/docker/daemon.json"
}

func TestCheckDaemonJSONPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	}
	fileInfo, err := os.Stat(etcDockerDaemon)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckDaemonJSONPerms)
	assert.Equal(t, "WARN", res.Status, "Daemon.json file permissions are not set, should not pass.")
	// Restore
	etcDockerDaemon = "/etc/docker/daemon.json"
}

func TestCheckDefaultOwnerSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	}
	res := checkOwnerSuccess(t, *testTarget, CheckDefaultOwner, true)
	assert.Equal(t, "PASS", res.Status, "Root:root ownership is set to /etc/default/docker file ownership, should pass")
	// Restore
	etcDefaultDocker = "/etc/default/docker"
	refGroup = "root"
}

func TestCheckDefaultOwnerFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	}
	res := checkOwnerFail(t, *testTarget, CheckDefaultOwner, true)
	assert.Equal(t, "WARN", res.Status, "Root:root ownership is not set to /etc/default/docker file ownership, should not pass.")
	// Restore
	etcDefaultDocker = "/etc/default/docker"
	refGroup = "root"
}

func TestCheckDefaultPermsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	}
	fileInfo, err := os.Stat(etcDefaultDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	}
	res := checkPermsSuccess(t, *testTarget, fileInfo, CheckDefaultPerms)
	assert.Equal(t, "PASS", res.Status, "Root:root ownership is set to /etc/default/docker file ownership, should pass")
	// Restore
	etcDefaultDocker = "/etc/default/docker"
}

func TestCheckDefaultPermsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	}
	fileInfo, err := os.Stat(etcDefaultDocker)
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	}
	res := checkPermsFail(t, *testTarget, fileInfo, CheckDefaultPerms)
	assert.Equal(t, "WARN", res.Status, "Root:root ownership is not set to /etc/default/docker file ownership, should not pass.")
	// Restore
	etcDefaultDocker = "/etc/default/docker"
}
