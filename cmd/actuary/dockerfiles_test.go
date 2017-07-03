package actuary


import (
	"os"
	"path/filepath"
	"testing"
	"os/user"
)

//3. Docker daemon configuration files
//mounting host directory method?

//For the functions that use systemdPaths, change the global variable to point to the testdata folder
func changeSystemDPath(t *testing.T) {

	path, err := filepath.Abs("testdata")
	if err != nil {
		t.Errorf("Could not get current user information %s", err)
	} 
	systemdPaths = []string{path}
}

func helperCheckOwner(t *testing.T, f func(tg Target) Result, err1 string, err2 string, gid bool) {
	//Covers all functions that involve checking the file's owner.
	//Sets the root user to be the test file's current user for the pass test case and to be the root on the fail case. 
	//Did it this way because could not make the test files created be "owned" by root 
	//potential problem: If the test files' owner is actually root -- is this possible with this setup?

	usr, err := user.Current() // change root user to current user for positive test case
	refUser = usr.Name


	//Only some of the functions test the gid, additional test signified by bool input
	if gid {
		gid, err := user.LookupGroupId(usr.Gid)
		refGroup = gid.Name

		if err != nil{
			t.Errorf("Could not get gid: %s", err)
		}
	}

	if err != nil {
		t.Errorf("Could not get current user information %s", err)
	} 

	res := f(testTarget)

	if res.Status != "PASS" {
			t.Errorf(err1)
	}

	//fail case

	refUser = "root"

	if gid{
		refGroup = "root"
	}

	res = f(testTarget)

	if res.Status == "PASS" {
			t.Errorf(err2)
	}
}

func helperCheckPerms(t *testing.T, fi os.FileInfo, f func(tg Target) Result, err1 string, err2 string) {
	//Covers all functions that involve checking the file's permissions
	//Sets the reference permissions in the original functions to the test files' permissions for the pass case
	//Same potential problem as above
	
	mode := fi.Mode().Perm()

	if err != nil {
		t.Errorf("Could not get docker.service file permissions %s", err)
	} 

	refPerms = uint32(mode)

	res := f(testTarget)

	if res.Status != "PASS" {
			t.Errorf(err1)
	}

	//fail case

	refPerms = uint32(mode) - 1

	res = f(testTarget)

	if res.Status == "PASS" {
			t.Errorf(err2)
	}
}


func TestCheckServiceOwner(t *testing.T) {
	
	changeSystemDPath(t)

	helperCheckOwner(t, CheckServiceOwner, "Root set to docker.service owner, should pass", "Docker.service owner is not set to root, should not pass.", false)
}

func TestCheckServicePerms(t *testing.T) {
	
	changeSystemDPath(t)

	fileInfo, err := lookupFile("docker.service", systemdPaths)

	if err != nil{
		t.Errorf("Could not lookup file docker.service: %s", err)
	}

	helperCheckPerms(t, fileInfo, CheckServicePerms, "Docker.service permissions set, should pass.", "Docker.service permissions not set, should not pass.")

	//restore
	refPerms = 0644
}

func TestCheckSocketOwner(t *testing.T) {
	
	changeSystemDPath(t)

	helperCheckOwner(t, CheckSocketOwner, "Root set to docker.socket owner, should pass", "Docker.socket owner not set, should not pass.", false)

}

func TestCheckSocketPerms(t *testing.T) {
	
	changeSystemDPath(t)

	fileInfo, err := lookupFile("docker.socket", systemdPaths)
	
	if err != nil {
		t.Errorf("Could not get docker.socket file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckSocketPerms, "Docker.socket permissions set, should pass.", "Docker.socket permissions not set, should not pass.")

	//restore 
	refPerms = 0644
}

func TestCheckDockerDirOwner(t *testing.T) {
	
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	helperCheckOwner(t, CheckDockerDirOwner, "Root set to /etc/docker directory ownership, should pass", "/etc/docker directory ownership != root, should not pass.", false)

	//restore
	etcDocker = "etc/Docker"
}

func TestCheckDockerDirPerms(t *testing.T) {

	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	fileInfo, err := os.Stat(etcDocker)

	if err != nil {
		t.Errorf("Could not get /etc/docker file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckDockerDirPerms, "/etc/docker permissions set, should pass.", "/etc/docker permissions not set, should not pass.")

	//restore 

	refPerms = 0755
	etcDocker = "etc/Docker"
	
}

func TestCheckRegistryCertOwner(t *testing.T) {

	//Original function .ReadDir called on a relative path, seems wrong...

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

	// res := CheckRegistryCertOwner(testTarget)

	// if res.Status != "PASS" {
	// 		t.Errorf("Root set to /etc/docker directory ownership, should pass" )
	// }

	// refUser = "root"

	// res = CheckRegistryCertOwner(testTarget)

	// if res.Status == "PASS" {
	// 		t.Errorf("/etc/docker directory ownership != root, should not pass." )
	// }

	// //restore
	// etcDockerCert = "etc/Docker/certs.d"

}

func TestCheckRegistryCertPerms(t *testing.T) {
 //Same problem as above
}

func TestCheckCACertOwner(t *testing.T) {
	//Following 7 tests are combinations of tests from dockerconf_test.go and other test functions within dockerfiles_test.go
	//Insert dummy test file by replacing call to procSetUp
	//PROBLEM: Using a file created and placed in an arbitrary folder (etcDocker) 
	//because could not find the expected certPath value (nil currently). Shouldn't matter, but not ideal.

	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	helperCheckOwner(t, CheckCACertOwner, "Root:root is set to TLS CA certificate file ownership, should pass.", "Root:root is not set to TLS CA certificate file ownership, should not pass.", false)

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
}

func TestCheckCACertPerms(t *testing.T) {

	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	fileInfo, err := os.Stat(etcDocker)
	
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckCACertPerms, "TLS CA certificate file permissions are set correctly, should pass", "File has less restrictive permissions than expected, should not pass.")

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckServerCertOwner(t *testing.T) {
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	helperCheckOwner(t, CheckServerCertOwner, "Root:root is set to Docker server certificate file ownership, should pass.", "Root:root is not set to Docker server certificate file ownership, should not pass.", false)

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
}

func TestCheckServerCertPerms(t *testing.T) {
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	fileInfo, err := os.Stat(etcDocker)
	
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckServerCertPerms, "Docker server certificate file permissions are set, should pass", "Docker server certificate file permissions are not set, should not pass.")

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
	refPerms = 0444
}

func TestCheckCertKeyOwner(t *testing.T) {
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	helperCheckOwner(t, CheckCertKeyOwner, "Root:root is set to Docker server certificate key file ownership, should pass.", "Root:root is not set to Docker server certificate key file ownership, should not pass.", true)

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
	
}

func TestCheckCertKeyPerms(t *testing.T) {
	etcDocker, err = filepath.Abs("testdata/etc/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker %s", err)
	} 

	procHelper = func(procname string, tlsOpt string) (val string){
		val = etcDocker
		return
	}

	fileInfo, err := os.Stat(etcDocker)
	
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckCertKeyPerms, "Docker server certificate key file permissions are set, should pass", "Docker server certificate key file permissions are not set, should not pass.")

	//restore

	procHelper = procSetUp
	etcDocker = "etc/Docker"
	refPerms = 0400
}

func TestCheckDockerSockOwner(t *testing.T) {
	
	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	} 

	helperCheckOwner(t, CheckDockerSockOwner, "Docker socket file ownership is set to root:docker, should pass", "Docker socket file ownership is not set to root:docker, should not pass.", true)

	//restore

	varRunDockerSock = "/var/run/docker.sock"
	refGroup = "docker"

}

func TestCheckDockerSockPerms(t *testing.T) {

	varRunDockerSock, err = filepath.Abs("testdata/var/run/docker.sock")
	
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock: %s", err)
	} 

	fileInfo, err := os.Stat(varRunDockerSock)
	
	if err != nil {
		t.Errorf("Could not get testdata/var/run/docker.sock file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckDockerSockPerms, "Docker sock file permissions are set, should pass", "Docker sock file permissions are not set, should not pass.")

	//restore

	varRunDockerSock = "/var/run/docker.sock"
}

func TestCheckDaemonJSONOwner(t *testing.T) {

	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	} 

	helperCheckOwner(t, CheckDaemonJSONOwner, "Root:root ownership is set to Daemon.json file's owner, should pass", "root:root ownership is not set to Daemon.json file's owner, should not pass.", true)

	//restore

	etcDockerDaemon = "/etc/docker/daemon.json"
	refGroup = "root"
}

func TestCheckDaemonJSONPerms(t *testing.T) {

	etcDockerDaemon, err = filepath.Abs("testdata/etc/docker/daemon.json")
	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json: %s", err)
	} 

	fileInfo, err := os.Stat(etcDockerDaemon)

	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	} 
	
	helperCheckPerms(t, fileInfo, CheckDaemonJSONPerms, "daemon.json file permissions are set, should pass", "daemon.json file permissions are not set, should not pass.")

	//restore

	etcDockerDaemon = "/etc/docker/daemon.json"
}

func TestCheckDefaultOwner(t *testing.T) {
	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	} 

	helperCheckOwner(t, CheckDefaultOwner, "Root:root ownership is set to /etc/default/docker file ownership, should pass", "Root:root ownership is not set to /etc/default/docker file ownership, should not pass.", true)

	//restore

	etcDefaultDocker = "/etc/default/docker"
	refGroup = "root"

}

func TestCheckDefaultPerms(t *testing.T) {

	etcDefaultDocker, err = filepath.Abs("testdata/etc/default/docker")
	if err != nil {
		t.Errorf("Could not get testdata/etc/default/docker: %s", err)
	} 

	fileInfo, err := os.Stat(etcDefaultDocker)

	if err != nil {
		t.Errorf("Could not get testdata/etc/docker/daemon.json file permissions %s", err)
	} 

	helperCheckPerms(t, fileInfo, CheckDefaultPerms, "Root:root ownership is set to /etc/default/docker file ownership, should pass", "Root:root ownership is not set to /etc/default/docker file ownership, should not pass.")

	//restore

	etcDefaultDocker = "/etc/default/docker"

}