package actuary


import (
	//"os"\
	//"fmt"

	"encoding/json"
	//"log"
	//"io/ioutil"

	"testing"
	//"strconv"
	//"io"
	//"net/http" //Package http provides HTTP client and server implementations.
	//"net/http/httptest" //Package httptest provides utilities for HTTP testing.
	"github.com/docker/engine-api/types"
	//"github.com/docker/engine-api/types/container"
	//"github.com/docker/go-connections/nat"	
	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	//"github.com/docker/docker/api"
	//"github.com/gorilla/mux"
	//"github.com/diogomonica/actuary/actuary"


)


//5. Container Runtime
	//for all container runtime tests, simplify to one container

func containerTestsHelper(t *testing.T, orig func(t Target) Result, f func(c Container, i int) Container, err1 string, err2 string){

	temp := testTarget.Containers
	testTarget.Containers = ContainerList{testTarget.Containers[0]}

	//log.Printf("%v", testTarget)

	for i := 0; i< 2; i++{	

		//Update the test containers (within testTarget to either pass or fail, depending on i)
		testTarget.Containers[0] = f(testTarget.Containers[0], i)

		//Run the function to be tested on testTarget
		res := orig(testTarget)

		if i == 0 && res.Status != "PASS" {
			t.Errorf(err1)
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf(err2)
		}	
	}

	//restore
	testTarget.Containers = temp 
}


func TestCheckAppArmor(t *testing.T) {
	//all containers should have AppArmor profile

	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.AppArmorProfile = "app armor"
		}else {
			c.Info.AppArmorProfile = ""
		}

		return c
	}	

	containerTestsHelper(t, CheckAppArmor, f, "All containers have app armor profile, should pass.", "Container without app armor profile, should not pass.")
}

func TestCheckSELinux(t *testing.T) {

	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.SecurityOpt = []string{"SELinux", "Array"}
		}else {
			c.Info.HostConfig.SecurityOpt = nil
		}

		return c
	}	

	containerTestsHelper(t, CheckSELinux, f, "All containers have SELinux options, should have passed.", "No containers have SELinux options, should not have passed.")
}


func TestCheckKernelCapabilities(t *testing.T) {
	
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.CapAdd =  nil
		}else {
			c.Info.HostConfig.CapAdd = []string{"added", "capabilities"}
		}

		return c
	}	

	containerTestsHelper(t, CheckKernelCapabilities, f, "No containers running with added capabilities, should have passed.", "Containers running with added capabilities, should not have passed.")
}


func TestCheckPrivContainers(t *testing.T) {

	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.Privileged  =  false
		}else {
			c.Info.HostConfig.Privileged  = true
		}

		return c
	}	
	containerTestsHelper(t, CheckPrivContainers, f, "No containers are privileged, should have passed.", "Containers are privileged, should not have passed.")
}

func TestCheckSensitiveDirs(t *testing.T) {
	
	f := func(c Container, i int) (Container) { 
		mounts := c.Info.Mounts

		if i == 0 {
			for m, _ := range mounts {
				c.Info.Mounts[m].Source = "mount"
				c.Info.Mounts[m].RW = false
			}
		}else {
			for m, _ := range mounts {
				c.Info.Mounts[m].Source = "/dev"
				c.Info.Mounts[m].RW = true
			}
		}

		return c
	}	
	containerTestsHelper(t, CheckSensitiveDirs, f, "No sensitive host system directories mounted on containers, should have passed.", "Sensitive host system directories mounted on containers, should not have passed.")
}

func TestCheckSSHRunning(t *testing.T) {
// GET "/containers/{name:.*}/top"
	var processList = types.ContainerProcessList{
					Titles: []string{"UID", "PID","PPID","C","STIME","TTY","TIME","CMD"},
					Processes: [][]string{{"root","13642","882","0","17:03","pts/0","00:00:00","/bin/bash"}, 
										{"root", "13735","13642","0","17:06","pts/0","00:00:00","sleep 10"}},
					}

	temp := testTarget.Containers
	testTarget.Containers =  ContainerList{testTarget.Containers[0]}


	for i := 0; i< 2; i++{
		pJSON, err := json.Marshal(processList)

		if err != nil {
			t.Errorf("Could not convert process list to json.")
		}

		p := callPairing{"/containers/" + testTarget.Containers[0].ID +"/top", pJSON}

		ts := testServer(t, p)
	
		res := CheckSSHRunning(testTarget)

		defer ts.Close()

		if i == 0 && res.Status != "PASS" {
			t.Errorf("No containers running SSH service, should pass" )
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf("Container running SSH service, should not pass" )
		}
		
		//test fail case
		processList.Processes[0][3] = "ssh"
	}

		testTarget.Containers = temp
 }

func TestCheckPrivilegedPorts(t *testing.T) {

	// f := func(c Container, i int) (Container) { 
	// 	if i == 0 {
	// 		pb1 := nat.PortBinding{"hostIp", "1000"}
	// 		pb2 := nat.PortBinding{"hostIp", "1000"}
	// 		portm := nat.PortMap{"80/tcp": {pb1, pb2}} 
	// 		c.Info.NetworkSettings.Ports = portm
	// 	}else {
	// 		c.Info.NetworkSettings.Ports = nat.PortMap{"80/tcp": {"hostIp", "1000"}, {"hostIp", "1000"}}
	// 	}

	// 	return c
	// }	
	// containerTestsHelper(t, CheckPrivilegedPorts, f, "No ports are privileged, should have passed.", "Ports are privileged, should not have passed.")
}	


func TestCheckNeededPorts(t *testing.T) {
	
}

func TestCheckHostNetworkMode(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.NetworkMode  = ""
		}else {
			c.Info.HostConfig.NetworkMode = "host"
		}

		return c
	}	
	containerTestsHelper(t, CheckHostNetworkMode, f, "No containers are privileged, should have passed.", "Containers are privileged, should not have passed.")
}

func TestCheckMemoryLimits(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.Memory  = 10.0
		}else {
			c.Info.HostConfig.Memory = 0
		}

		return c
	}	
	containerTestsHelper(t, CheckMemoryLimits, f, "No containers have unlimited memory, should have passed.", "Container has unlimited memory, should not have passed.")
}

func TestCheckCPUShares(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.CPUShares = 100
		}else {
			c.Info.HostConfig.CPUShares = 0
		}

		return c
	}	
	containerTestsHelper(t, CheckCPUShares, f, "No containers with CPU sharing disable, should have passed.", "Containers with CPU sharing disabled, should not have passed.")
}

func TestCheckReadonlyRoot(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.ReadonlyRootfs = true
		}else {
			c.Info.HostConfig.ReadonlyRootfs = false
		}

		return c
	}	
	containerTestsHelper(t, CheckReadonlyRoot, f, "Containers all have read only root filesystem, should have passed.", "Containers' root FS is not mounted as read-only, should not have passed.")
}

func TestCheckBindHostInterface(t *testing.T) {
	// f := func(c Container, i int) (Container) { 
	// 	if i == 0 {
	// 		pb1 := nat.PortBinding{"1.0.0.0", "hostport"}
	// 		pb2 := nat.PortBinding{"1.0.0.0", "hostport"}
	// 		portm := nat.PortMap{"80/tcp": {pb1, pb2}} 
	// 		c.Info.NetworkSettings.Ports = portm
	// 	}else {
	// 		pb1 = nat.PortBinding{"0.0.0.0", "hostport"}
	// 		pb2 = nat.PortBinding{"0.0.0.0", "hostport"}
	// 		portm = nat.PortMap{"80/tcp": {pb1, pb2}} 
	// 		c.Info.NetworkSettings.Ports = portm
	// 	}

	// 	return c
	// }	
	// containerTestsHelper(t, CheckBindHostINterface, f, "Incoming container traffic bound to host interface, should have passed.", "Container traffic not bound to specific host interface, should not have passed.")
}

func TestCheckRestartPolicy(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.RestartPolicy.Name = "on-failure"
			c.Info.HostConfig.RestartPolicy.MaximumRetryCount = 5
		}else {
			c.Info.HostConfig.RestartPolicy.Name = ""
			c.Info.HostConfig.RestartPolicy.MaximumRetryCount = 0
		}

		return c
	}	
	containerTestsHelper(t, CheckRestartPolicy, f, "Containers all have restart policy set to 5, should have passed.", "Containers with no restart policy, should not have passed.")
}

func TestCheckHostNamespace(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.PidMode = ""
		}else {
			c.Info.HostConfig.PidMode = "host"		
		}

		return c
	}	
	containerTestsHelper(t, CheckHostNamespace, f, "Containers do not share the host's process namespace, should have passed.", "Containers sharing host's process namespace, should not have passed.")
}

func TestCheckIPCNamespace(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.IpcMode = ""
		}else {
			c.Info.HostConfig.IpcMode = "host"		
		}

		return c
	}	
	containerTestsHelper(t, CheckIPCNamespace, f, "Containers do not share the host's IPC namespace, should have passed.", "Containers sharing host's IPC namespace, should not have passed.")
}

func TestCheckHostDevices(t *testing.T) {
	// f := func(c Container, i int) (Container) { 

	// 	if i == 0 {
	// 		d1 := container.DeviceMapping{"1", "2", "3"}
	// 		d2 := container.DeviceMapping{"1", "2", "3"}
	// 		deviceList := []container.DeviceMapping{d1, d2}
	// 		c.Info.HostConfig.Devices = deviceList
	// 	}else {
	// 		c.Info.HostConfig.Devices = nil		
	// 	}

	// 	return c
	// }	
	// containerTestsHelper(t, CheckHostDevices, f, "Host devices not exposed to containers, should have passed.", "Host devices directly exposed to containers, should not have passed.")
 }

func TestCheckDefaultUlimit(t *testing.T) {
	// f := func(c Container, i int) (Container) { 

	// 	if i == 0 {
	// 		c.Info.HostConfig.Ulimits = 
	// 	}else {
	// 		c.Info.HostConfig.Ulimits = nil		
	// 	}

	// 	return c
	// }	
	// containerTestsHelper(t, CheckIPCNamespace, f, "Containers do not override default ulimit, should have passed.", "Containers overriding default ulimit, should not have passed.")
}

func TestCheckMountPropagation(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			mounts := c.Info.Mounts 
			for _, mount := range mounts {
				mount.Mode = "" 
			}	
		}else {
			mounts := c.Info.Mounts 
			mounts[0].Mode = "shared"
		}

		return c
	}	
	containerTestsHelper(t, CheckMountPropagation, f, "Mount propagation mode not set to shared, should have passed.", "Containers have mount propagation set to shared, should not have passed.")
}

func TestCheckUTSnamespace(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.UTSMode = ""
		}else {
			c.Info.HostConfig.UTSMode = "host"
		}

		return c
	}	
	containerTestsHelper(t, CheckUTSnamespace, f, "Containers do not share host's UTS namespace, should have passed.", "Containers share host's UTS namespace, should not have passed.")
}

func TestCheckSeccompProfile(t *testing.T) {
	f := func(c Container, i int) (Container) { 

		if i == 0 {
			c.Info.HostConfig.SecurityOpt = []string{"seccomp", "not disabled"}
		}else {
			c.Info.HostConfig.SecurityOpt = []string{"seccomp:unconfined"}
		}

		return c
	}	
	containerTestsHelper(t, CheckSeccompProfile, f, "Seccomp not disabled, should have passed.", "Containers running with seccomp disabled, should not have passed.")
}

func TestCheckCgroupUsage(t *testing.T) {
	f := func(c Container, i int) (Container){

		if i == 0 {
			c.Info.HostConfig.CgroupParent = ""
		}else {
			c.Info.HostConfig.CgroupParent = "cgroup"}

		return c
	}
		
	containerTestsHelper(t, CheckCgroupUsage, f, "Containers all using default cgroup, should have passed.", "Container not using default cgroup, should not have passed.")
}

func TestCheckAdditionalPrivs(t *testing.T) {
	f := func(c Container, i int) (Container){

		if i == 0 {
			c.Info.HostConfig.SecurityOpt = []string{"no-new-privileges"}
		}else {
			c.Info.HostConfig.SecurityOpt = []string{""}
		}

		return c
	}
		
	containerTestsHelper(t, CheckAdditionalPrivs, f, "Containers restricted from aquiring additional privileges, should have passed.", "Containers unrestricted from acquiring additional privileges, should not have passed.")
}