package actuary

import (
	"encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"testing"
)

// 5. Container Runtime
// For all container runtime tests, simplify to one container (testTarget has only one container in containerList)
func containerTestsHelper(t *testing.T, testTarget Target, orig func(t Target) Result, f func(c Container) Container, err string, expected string) {
	temp := testTarget.Containers
	testTarget.Containers = ContainerList{testTarget.Containers[0]}
	// Update the test containers with f to either pass or fail
	testTarget.Containers[0] = f(testTarget.Containers[0])
	// Run the function to be tested on testTarget and determine results
	res := orig(testTarget)
	assert.Equal(t, expected, res.Status, err)
	// Restore
	testTarget.Containers = temp
}

// Function to be passed into containerTestsHelper
// Ensures passing containers, then failing containers in testTarget
func TestCheckAppArmorSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.AppArmorProfile = "app armor"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckAppArmor, f, "All containers have app armor profile, should pass.", "PASS")
}

func TestCheckAppArmorFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.AppArmorProfile = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckAppArmor, f, "Container without app armor profile, should not pass.", "WARN")
}

func TestCheckSELinuxSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = []string{"SELinux", "Array"}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSELinux, f, "All containers have SELinux options, should have passed.", "PASS")
}

func TestCheckSELinuxFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = nil
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSELinux, f, "No containers have SELinux options, should not have passed.", "WARN")
}

func TestCheckKernelCapabilitiesSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CapAdd = nil
		return c
	}
	containerTestsHelper(t, *testTarget, CheckKernelCapabilities, f, "No containers running with added capabilities, should have passed.", "PASS")
}

func TestCheckKernelCapabilitiesFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CapAdd = []string{"added", "capabilities"}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckKernelCapabilities, f, "Containers running with added capabilities, should not have passed.", "WARN")
}

func TestCheckPrivContainersSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.Privileged = false
		return c
	}
	containerTestsHelper(t, *testTarget, CheckPrivContainers, f, "No containers are privileged, should have passed.", "PASS")
}

func TestCheckPrivContainersFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.Privileged = true
		return c
	}
	containerTestsHelper(t, *testTarget, CheckPrivContainers, f, "Containers are privileged, should not have passed.", "WARN")
}

func TestCheckSensitiveDirsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		m := types.MountPoint{Source: "mount", RW: false}
		c.Info.Mounts = []types.MountPoint{m}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSensitiveDirs, f, "No sensitive host system directories mounted on containers, should have passed.", "PASS")
}

func TestCheckSensitiveDirsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		m := types.MountPoint{Source: "/dev", RW: true}
		c.Info.Mounts = []types.MountPoint{m}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSensitiveDirs, f, "Sensitive host system directories mounted on containers, should not have passed.", "WARN")
}

func TestCheckSSHRunningSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var processList = container.ContainerTopOKBody{
		Processes: [][]string{{"root", "13642", "882", "0", "17:03", "pts/0", "00:00:00", "/bin/bash"},
			{"root", "13735", "13642", "0", "17:06", "pts/0", "00:00:00", "sleep 10"}},
		Titles: []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"},
	}
	temp := testTarget.Containers
	testTarget.Containers = ContainerList{testTarget.Containers[0]}
	pJSON, err := json.Marshal(processList)

	if err != nil {
		t.Errorf("Could not convert process list to json.")
	}
	p := callPairing{"/containers/" + testTarget.Containers[0].ID + "/top", pJSON}
	ts := testTarget.testServer(t, p)
	res := CheckSSHRunning(*testTarget)
	defer ts.Close()
	assert.Equal(t, "PASS", res.Status, "No containers running SSH service, should pass")
	testTarget.Containers = temp
}

func TestCheckSSHRunningFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var processList = container.ContainerTopOKBody{
		Processes: [][]string{{"root", "13642", "882", "0", "17:03", "pts/0", "00:00:00", "/bin/bash"},
			{"root", "13735", "13642", "0", "17:06", "pts/0", "00:00:00", "sleep 10"}},
		Titles: []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"},
	}
	processList.Processes[0][3] = "ssh"

	temp := testTarget.Containers
	testTarget.Containers = ContainerList{testTarget.Containers[0]}
	pJSON, err := json.Marshal(processList)

	if err != nil {
		t.Errorf("Could not convert process list to json.")
	}
	p := callPairing{"/containers/" + testTarget.Containers[0].ID + "/top", pJSON}
	ts := testTarget.testServer(t, p)
	res := CheckSSHRunning(*testTarget)
	defer ts.Close()
	assert.Equal(t, "WARN", res.Status, "Container running SSH service, should not pass")
	testTarget.Containers = temp
}

func TestCheckPrivilegedPorts(t *testing.T) {
	//PROBLEM: difficulty manipulating portbinding type

	// f := func(c Container, i int) (Container) {
	// 	ports := c.Info.NetworkSettings.Ports
	// 	for _, port := range ports {
	// 		for _, portmap := range port {
	// 			if i == 0 {
	// 				portmap.HostPort = "1025"
	// 			}else {
	// 				portmap.HostPort = "1000"
	// 			}
	// 		}
	// 	}

	// 	return c
	// }

	// containerTestsHelper(t, *testTarget, CheckPrivilegedPorts, f, "No ports are privileged, should have passed.", "Ports are privileged, should not have passed.")

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
	// containerTestsHelper(t, *testTarget, CheckPrivilegedPorts, f, "No ports are privileged, should have passed.", "Ports are privileged, should not have passed.")
}

func TestCheckNeededPorts(t *testing.T) {
	//same problem as previous function
}

func TestCheckHostNetworkModeSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.NetworkMode = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckHostNetworkMode, f, "No containers are privileged, should have passed.", "PASS")
}

func TestCheckHostNetworkModeFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.NetworkMode = "host"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckHostNetworkMode, f, "Containers are privileged, should not have passed.", "WARN")
}

func TestCheckMemoryLimitsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.Memory = 10.0
		return c
	}
	containerTestsHelper(t, *testTarget, CheckMemoryLimits, f, "No containers have unlimited memory, should have passed.", "PASS")
}

func TestCheckMemoryLimitsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.Memory = 0
		return c
	}
	containerTestsHelper(t, *testTarget, CheckMemoryLimits, f, "Container has unlimited memory, should not have passed.", "WARN")
}

func TestCheckCPUSharesSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CPUShares = 100
		return c
	}
	containerTestsHelper(t, *testTarget, CheckCPUShares, f, "No containers with CPU sharing disable, should have passed.", "PASS")
}

func TestCheckCPUSharesFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CPUShares = 0
		return c
	}
	containerTestsHelper(t, *testTarget, CheckCPUShares, f, "Containers with CPU sharing disabled, should not have passed.", "WARN")
}

func TestCheckReadonlyRootSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.ReadonlyRootfs = true
		return c
	}
	containerTestsHelper(t, *testTarget, CheckReadonlyRoot, f, "Containers all have read only root filesystem, should have passed.", "PASS")
}

func TestCheckReadonlyRootFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.ReadonlyRootfs = false
		return c
	}
	containerTestsHelper(t, *testTarget, CheckReadonlyRoot, f, "Containers' root FS is not mounted as read-only, should not have passed.", "WARN")
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
	// containerTestsHelper(t, *testTarget, CheckBindHostINterface, f, "Incoming container traffic bound to host interface, should have passed.", "Container traffic not bound to specific host interface, should not have passed.")
}

func TestCheckRestartPolicySuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.RestartPolicy.Name = "on-failure"
		c.Info.HostConfig.RestartPolicy.MaximumRetryCount = 5
		return c
	}
	containerTestsHelper(t, *testTarget, CheckRestartPolicy, f, "Containers all have restart policy set to 5, should have passed.", "PASS")
}

func TestCheckRestartPolicyFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.RestartPolicy.Name = ""
		c.Info.HostConfig.RestartPolicy.MaximumRetryCount = 0
		return c
	}
	containerTestsHelper(t, *testTarget, CheckRestartPolicy, f, "Containers with no restart policy, should not have passed.", "WARN")
}

func TestCheckHostNamespaceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.PidMode = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckHostNamespace, f, "Containers do not share the host's process namespace, should have passed.", "PASS")
}

func TestCheckHostNamespaceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.PidMode = "host"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckHostNamespace, f, "Containers sharing host's process namespace, should not have passed.", "WARN")
}

func TestCheckIPCNamespaceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.IpcMode = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckIPCNamespace, f, "Containers do not share the host's IPC namespace, should have passed.", "PASS")
}

func TestCheckIPCNamespaceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.IpcMode = "host"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckIPCNamespace, f, "Containers sharing host's IPC namespace, should not have passed.", "WARN")
}

func TestCheckHostDevices(t *testing.T) {

	// log.Printf("DEVICES: %v", testTarget.Containers[0].Info.HostConfig.Devices)
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
	// containerTestsHelper(t, *testTarget, CheckHostDevices, f, "Host devices not exposed to containers, should have passed.", "Host devices directly exposed to containers, should not have passed.")
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
	// containerTestsHelper(t, *testTarget, CheckIPCNamespace, f, "Containers do not override default ulimit, should have passed.", "Containers overriding default ulimit, should not have passed.")
}

func TestCheckMountPropagationSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		m := types.MountPoint{Mode: ""}
		c.Info.Mounts = []types.MountPoint{m}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckMountPropagation, f, "Mount propagation mode not set to shared, should have passed.", "PASS")
}

func TestCheckMountPropagationFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		m := types.MountPoint{Mode: "shared"}
		c.Info.Mounts = []types.MountPoint{m}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckMountPropagation, f, "Containers have mount propagation set to shared, should not have passed.", "WARN")
}

func TestCheckUTSnamespaceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.UTSMode = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckUTSnamespace, f, "Containers do not share host's UTS namespace, should have passed.", "PASS")
}

func TestCheckUTSnamespaceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.UTSMode = "host"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckUTSnamespace, f, "Containers share host's UTS namespace, should not have passed.", "WARN")
}

func TestCheckSeccompProfileSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = []string{"seccomp", "not disabled"}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSeccompProfile, f, "Seccomp not disabled, should have passed.", "PASS")
}

func TestCheckSeccompProfileFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = []string{"seccomp:unconfined"}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckSeccompProfile, f, "Containers running with seccomp disabled, should not have passed.", "WARN")
}

func TestCheckCgroupUsageSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CgroupParent = ""
		return c
	}
	containerTestsHelper(t, *testTarget, CheckCgroupUsage, f, "Containers all using default cgroup, should have passed.", "PASS")
}

func TestCheckCgroupUsageFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.CgroupParent = "cgroup"
		return c
	}
	containerTestsHelper(t, *testTarget, CheckCgroupUsage, f, "Container not using default cgroup, should not have passed.", "WARN")
}

func TestCheckAdditionalPrivsSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = []string{"no-new-privileges"}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckAdditionalPrivs, f, "Containers restricted from aquiring additional privileges, should have passed.", "PASS")
}

func TestCheckAdditionalPrivsFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	f := func(c Container) Container {
		c.Info.HostConfig.SecurityOpt = []string{""}
		return c
	}
	containerTestsHelper(t, *testTarget, CheckAdditionalPrivs, f, "Containers unrestricted from acquiring additional privileges, should not have passed.", "WARN")
}
