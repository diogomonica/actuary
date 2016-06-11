/*
Package checks - 5 Container Runtime
The ways in which a container is started governs a lot security implications. It is possible to
provide potentially dangerous runtime parameters that might compromise the host and
other containers on the host. Verifying container runtime is thus very important.
*/
package actuary

import (
	"fmt"
	"log"

	"strconv"
	"strings"
)

func CheckAppArmor(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		if container.Info.AppArmor() == "" {
			badContainers = append(badContainers, container.ID)
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with no AppArmor profile: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckSELinux(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		if container.Info.SELinux() == nil {
			badContainers = append(badContainers, container.ID)
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with no SELinux options: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckKernelCapabilities(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.3 Restrict Linux Kernel Capabilities within containers"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		if container.Info.KernelCapabilities() != nil {
			badContainers = append(badContainers, container.ID)
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers running with added capabilities: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckPrivContainers(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.4 Do not use privileged containers"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		if container.Info.Privileged() == true {
			badContainers = append(badContainers, container.ID)
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Privileged containers found: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckSensitiveDirs(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.5 Do not mount sensitive host system directories on containers "
	sensitiveDirs := []string{"/dev", "/etc", "/lib", "/proc", "/sys", "/usr"}
	containers := t.Containers

	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mounts := container.Info.Mounts
		for _, mount := range mounts {
			for _, dir := range sensitiveDirs {
				if strings.HasPrefix(mount.Source, dir) && mount.RW == true {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Sensitive directories mounted on containers: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckSSHRunning(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.6 Do not run ssh within containers"
	containers := t.Containers

	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		procs, err := t.Client.ContainerTop(container.ID, []string{})
		if err != nil {
			log.Printf("unable to retrieve proc list for container %s: %v", container.ID, err)
		}
		//proc fields are [UID PID PPID C STIME TTY TIME CMD]
		for _, proc := range procs.Processes {
			procname := proc[7]
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
	var badContainers []string
	res.Name = "5.7 Do not map privileged ports within containers"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		ports := container.Info.NetworkSettings.Ports
		for _, port := range ports {
			for _, portmap := range port {
				hostPort, _ := strconv.Atoi(portmap.HostPort)
				if hostPort < 1024 {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with mapped privileged ports: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckNeededPorts(t Target) (res Result) {
	var containerPort map[string][]string
	containerPort = make(map[string][]string)
	res.Name = "5.8 Open only needed ports on container"
	containers := t.Containers
	if !containers.Running() {
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
	var badContainers []string
	res.Name = "5.9 Do not use host network mode on container"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}

	for _, container := range containers {
		mode := container.Info.HostConfig.NetworkMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Privileged containers found: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckMemoryLimits(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.10 Limit memory usage for container"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mem := container.Info.HostConfig.Memory
		if mem == 0 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with no memory limits: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckCPUShares(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.11 Set container CPU priority appropriately"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		shares := container.Info.HostConfig.CPUShares
		if shares == 0 || shares == 1024 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with CPU sharing disabled: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckReadonlyRoot(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.12 Mount container's root filesystem as read only"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		readonly := container.Info.HostConfig.ReadonlyRootfs
		if readonly == false {
			badContainers = append(badContainers, container.ID)
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers' root FS is not mounted as read-only: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckBindHostInterface(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.13 Bind incoming container traffic to a specific host interface"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		ports := container.Info.NetworkSettings.Ports
		for _, port := range ports {
			for _, portmap := range port {
				if portmap.HostIP == "0.0.0.0" {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers traffic not bound to specific host interface: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckRestartPolicy(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.14 Set the 'on-failure' container restart policy to 5"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		policy := container.Info.HostConfig.RestartPolicy
		if policy.Name != "on-failure" && policy.MaximumRetryCount < 5 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with no restart policy: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckHostNamespace(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.15 Do not share the host's process namespace"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mode := container.Info.HostConfig.PidMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers sharing host's process namespace: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckIPCNamespace(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.16 Do not share the host's IPC namespace"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mode := container.Info.HostConfig.IpcMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers sharing host's IPC namespace: %s",
			badContainers)
		res.Fail(output)
	}

	return
}

func CheckHostDevices(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.17 Do not directly expose host devices to containers"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}

	for _, container := range containers {
		devices := container.Info.HostConfig.Devices
		if len(devices) != 0 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Host devices exposed. Check your permissions: %s",
			badContainers)
		res.Fail(output)

	}
	return
}

func CheckDefaultUlimit(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.18 Override default ulimit at runtime only if needed "
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		ulimit := container.Info.HostConfig.Ulimits
		if ulimit != nil {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers overriding default ulimit: %s",
			badContainers)
		res.Fail(output)

	}
	return
}

func CheckMountPropagation(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.19 Do not set mount propagation mode to shared"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mounts := container.Info.Mounts
		for _, mount := range mounts {
			if mount.Mode == "shared" {
				badContainers = append(badContainers, container.ID)
				break
			}
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers with mount propagation set to shared: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckUTSnamespace(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.20 Do not share the host's UTS namespace"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		mode := container.Info.HostConfig.UTSMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers sharing host's UTS namespace: %s",
			badContainers)
		res.Fail(output)
	}

	return
}

func CheckSeccompProfile(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.21 Do not disable default seccomp profile"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		seccomp := container.Info.HostConfig.SecurityOpt
		if len(seccomp) == 1 && seccomp[0] == "seccomp:unconfined" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers running with seccomp disabled: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckCgroupUsage(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.24 Confirm cgroup usage"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		cgroup := container.Info.HostConfig.CgroupParent
		if cgroup != "" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers not using default cgroup: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckAdditionalPrivs(t Target) (res Result) {
	var badContainers []string
	res.Name = "5.25 Restrict container from acquiring additional privileges"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		secopts := container.Info.HostConfig.SecurityOpt
		if len(secopts) == 0 {
			badContainers = append(badContainers, container.ID)
		} else {
			if !stringInSlice("no-new-privileges", secopts) {
				badContainers = append(badContainers, container.ID)
			}
		}
	}

	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers unrestricted from acquiring additional privileges: %s",
			badContainers)
		res.Fail(output)
	}
	return
}
