/*
Package checks - 5 Container Runtime
The ways in which a container is started governs a lot security implications. It is possible to
provide potentially dangerous runtime parameters that might compromise the host and
other containers on the host. Verifying container runtime is thus very important.
*/
package actuary

import (
	"fmt"
	//"log"
	"strconv"
	"strings"

	"golang.org/x/net/context"
)

func CheckAppArmor(t Target) (res Result) {
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	apparmor := func(c ContainerInfo) bool {
		if c.AppArmorProfile == "" {
			return false
		}
		return true
	}

	t.Containers.runCheck(&res, apparmor, "Containers with no AppArmor profile: %s")
	return
}

func CheckSELinux(t Target) (res Result) {
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}

	selinux := func(c ContainerInfo) bool {
		if c.HostConfig.SecurityOpt == nil {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, selinux, "Containers with no SELinux options: %s")
	return
}

func CheckKernelCapabilities(t Target) (res Result) {
	res.Name = "5.3 Restrict Linux Kernel Capabilities within containers"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}

	kernelCap := func(c ContainerInfo) bool {
		if c.HostConfig.CapAdd != nil {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, kernelCap, "Containers running with added capabilities: %s")
	return
}

func CheckPrivContainers(t Target) (res Result) {
	res.Name = "5.4 Do not use privileged containers"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}

	priv := func(c ContainerInfo) bool {
		if c.HostConfig.Privileged == true {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, priv, "Privileged containers found: %s")
	return
}

func CheckSensitiveDirs(t Target) (res Result) {
	res.Name = "5.5 Do not mount sensitive host system directories on containers "
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}

	sensitiveDirs := func(c ContainerInfo) bool {
		mounts := c.Mounts
		dirList := []string{"/dev", "/etc", "/lib", "/proc", "/sys", "/usr"}
		for _, mount := range mounts {			
			for _, dir := range dirList {
				if strings.HasPrefix(mount.Source, dir) && mount.RW == true {
					return false
				}
			}
		}
		return true
	}
	t.Containers.runCheck(&res, sensitiveDirs, "Sensitive directories mounted on containers: %s")
	return
}

func CheckSSHRunning(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.6 Do not run ssh within containers"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range t.Containers {
		procs, err := t.Client.ContainerTop(context.TODO(), container.ID, []string{})
		//log.Printf("ID: %s", container.ID)
		if err != nil {
			//log.Printf("unable to retrieve proc list for container %s: %v", container.ID, err)
		}
		//proc fields are [UID PID PPID C STIME TTY TIME CMD]
		for _, proc := range procs.Processes {
			procname := proc[3]
			//log.Printf("PROCNAME: %s", proc)
			if strings.Contains(procname, "ssh") {
				badContainers = append(badContainers, container.ID)
			}
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers running SSH service: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckPrivilegedPorts(t Target) (res Result) {
	res.Name = "5.7 Do not map privileged ports within containers"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	privPorts := func(c ContainerInfo) bool {
		ports := c.NetworkSettings.Ports
		//log.Printf("PORT: %v", ports)

		for _, port := range ports {
			for _, portmap := range port {
				hostPort, _ := strconv.Atoi(portmap.HostPort)
				if hostPort < 1024 {
					return false
				}
			}
		}
		return true
	}
	t.Containers.runCheck(&res, privPorts, "Containers with mapped privileged ports: %s")
	return
}

func CheckNeededPorts(t Target) (res Result) {
	var containerPort map[string][]string
	containerPort = make(map[string][]string)
	res.Name = "5.8 Open only needed ports on container"
	containers := t.Containers
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		ports := container.Info.NetworkSettings.Ports
		for key, _ := range ports {
			containerPort[container.ID] = append(containerPort[container.ID],
				string(key))
		}
	}
	res.Status = "INFO"
	res.Output = fmt.Sprintf("Containers with open ports: %v \n",
		containerPort)

	return res
}

func CheckHostNetworkMode(t Target) (res Result) {
	res.Name = "5.9 Do not use host network mode on container"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	hostMode := func(c ContainerInfo) bool {
		if c.HostConfig.NetworkMode != "host" {
			return true
		}
		return false
	}
	t.Containers.runCheck(&res, hostMode, "Privileged containers found: %s")
	return
}

func CheckMemoryLimits(t Target) (res Result) {
	res.Name = "5.10 Limit memory usage for container"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	
	memLim := func(c ContainerInfo) bool {
		if c.HostConfig.Memory != 0 {
			return true
		}
		return false
	}
	t.Containers.runCheck(&res, memLim, "Containers with no memory limits: %s")
	return
}

func CheckCPUShares(t Target) (res Result) {
	res.Name = "5.11 Set container CPU priority appropriately"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	cpuShares := func(c ContainerInfo) bool {
		shares := c.HostConfig.CPUShares
		if shares == 0 || shares == 1024 {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, cpuShares, "Containers with CPU sharing disabled: %s")
	return
}

func CheckReadonlyRoot(t Target) (res Result) {
	res.Name = "5.12 Mount container's root filesystem as read only"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	readOnly := func(c ContainerInfo) bool {
		return c.HostConfig.ReadonlyRootfs
	}
	t.Containers.runCheck(&res, readOnly, "Containers' root FS is not mounted as read-only: %s")
	return
}

func CheckBindHostInterface(t Target) (res Result) {
	res.Name = "5.13 Bind incoming container traffic to a specific host interface"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	bindHost := func(c ContainerInfo) bool {
		for _, port := range c.NetworkSettings.Ports {
			for _, portmap := range port {
				if portmap.HostIP == "0.0.0.0" {
					return false
				}
			}
		}
		return true
	}
	t.Containers.runCheck(&res, bindHost, "Containers traffic not bound to specific host interface: %s")
	return
}

func CheckRestartPolicy(t Target) (res Result) {
	res.Name = "5.14 Set the 'on-failure' container restart policy to 5"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	restartPolicy := func(c ContainerInfo) bool {
		policy := c.HostConfig.RestartPolicy
		if policy.Name != "on-failure" && policy.MaximumRetryCount < 5 {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, restartPolicy, "Containers with no restart policy: %s")
	return
}

func CheckHostNamespace(t Target) (res Result) {
	res.Name = "5.15 Do not share the host's process namespace"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	hostNamespace := func(c ContainerInfo) bool {
		if c.HostConfig.PidMode == "host" {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, hostNamespace, "Containers sharing host's process namespace: %s")
	return
}

func CheckIPCNamespace(t Target) (res Result) {
	res.Name = "5.16 Do not share the host's IPC namespace"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	ipc := func(c ContainerInfo) bool {
		if c.HostConfig.IpcMode == "host" {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, ipc, "Containers sharing host's IPC namespace: %s")
	return
}

func CheckHostDevices(t Target) (res Result) {
	res.Name = "5.17 Do not directly expose host devices to containers"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	hostDevices := func(c ContainerInfo) bool {
		if len(c.HostConfig.Devices) != 0 {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, hostDevices, "Host devices exposed. Check your permissions: %s")
	return
}

func CheckDefaultUlimit(t Target) (res Result) {
	res.Name = "5.18 Override default ulimit at runtime only if needed "
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	ulimit := func(c ContainerInfo) bool {
		if c.HostConfig.Ulimits != nil {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, ulimit, "Containers overriding default ulimit: %s")
	return
}

func CheckMountPropagation(t Target) (res Result) {
	res.Name = "5.19 Do not set mount propagation mode to shared"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	mountProp := func(c ContainerInfo) bool {
		for _, mount := range c.Mounts {
			if mount.Mode == "shared" {
				return false
			}
		}
		return true
	}
	t.Containers.runCheck(&res, mountProp, "Containers with mount propagation set to shared: %s")
	return
}

func CheckUTSnamespace(t Target) (res Result) {
	res.Name = "5.20 Do not share the host's UTS namespace"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	utsNamespace := func(c ContainerInfo) bool {
		if c.HostConfig.UTSMode == "host" {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, utsNamespace, "Containers sharing host's UTS namespace: %s")
	return
}

func CheckSeccompProfile(t Target) (res Result) {
	res.Name = "5.21 Do not disable default seccomp profile"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	secComp := func(c ContainerInfo) bool {
		seccomp := c.HostConfig.SecurityOpt
		if len(seccomp) == 1 && seccomp[0] == "seccomp:unconfined" {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, secComp, "Containers running with seccomp disabled: %s")
	return
}

func CheckCgroupUsage(t Target) (res Result) {
	res.Name = "5.24 Confirm cgroup usage"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	cgroup := func(c ContainerInfo) bool {
		if c.HostConfig.CgroupParent != "" {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, cgroup, "Containers not using default cgroup: %s")
	return
}

func CheckAdditionalPrivs(t Target) (res Result) {
	res.Name = "5.25 Restrict container from acquiring additional privileges"
	if !t.Containers.Running() {
		res.Skip("No running containers")
		return
	}
	privs := func(c ContainerInfo) bool {
		secopts := c.HostConfig.SecurityOpt
		if !stringInSlice("no-new-privileges", secopts) {
			return false
		}
		return true
	}
	t.Containers.runCheck(&res, privs, "Containers unrestricted from acquiring additional privileges: %s")
	return
}
