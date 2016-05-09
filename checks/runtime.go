/*
Package checks - 5 Container Runtime
The ways in which a container is started governs a lot security implications. It is possible to
provide potentially dangerous runtime parameters that might compromise the host and
other containers on the host. Verifying container runtime is thus very important.
*/
package checks

import (
	"fmt"

	"github.com/diogomonica/actuary"
	"github.com/docker/engine-api/client"

	"strconv"
	"strings"
)

func CheckAppArmor(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	containers := actuary.CreateContainerList(client)
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

func CheckSELinux(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	containers := actuary.CreateContainerList(client)
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

func CheckSingleMainProcess(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.3 Verify that containers are running only a single main process"
	containers := actuary.CreateContainerList(client)
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		procs, _ := client.ContainerTop(container.ID, []string{})
		mainPid := procs.Processes[0][1]
		//checks if there are different parent PIDs
		for _, proc := range procs.Processes[1:] {
			ppid := proc[2]
			if ppid != mainPid {
				badContainers = append(badContainers, container.ID)
			}
		}
	}
	if len(badContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers running more than one main process: %s",
			badContainers)
		res.Fail(output)
	}
	return
}

func CheckKernelCapabilities(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.4 Restrict Linux Kernel Capabilities within containers"
	containers := actuary.CreateContainerList(client)
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

func CheckPrivContainers(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.5 Do not use privileged containers"
	containers := actuary.CreateContainerList(client)
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

func CheckSensitiveDirs(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.6 Do not mount sensitive host system directories on containers "
	sensitiveDirs := []string{"/dev", "/etc", "/lib", "/proc", "/sys", "/usr"}
	containers := actuary.CreateContainerList(client)

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

func CheckSSHRunning(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.7 Do not run ssh within containers"
	containers := actuary.CreateContainerList(client)

	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		procs, _ := client.ContainerTop(container.ID, []string{})
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

func CheckPrivilegedPorts(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.8 Do not map privileged ports within containers"
	containers := actuary.CreateContainerList(client)
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

func CheckNeededPorts(client *client.Client) (res Result) {
	var containerPort map[string][]string
	containerPort = make(map[string][]string)
	res.Name = "5.9 Open only needed ports on container"
	containers := actuary.CreateContainerList(client)
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

func CheckHostNetworkMode(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.10 Do not use host network mode on container"
	containers := actuary.CreateContainerList(client)
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mode := info.HostConfig.NetworkMode
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

func CheckMemoryLimits(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.11 Limit memory usage for container"
	containers := actuary.CreateContainerList(client)
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mem := info.HostConfig.Memory
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

func CheckCPUShares(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.12 Set container CPU priority appropriately"
	containers := actuary.CreateContainerList(client)
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

func CheckReadonlyRoot(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.13 Mount container's root filesystem as read only"
	containers := actuary.CreateContainerList(client)
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

func CheckBindHostInterface(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.14 Bind incoming container traffic to a specific host interface"
	containers := actuary.CreateContainerList(client)
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

func CheckRestartPolicy(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.15 Set the 'on-failure' container restart policy to 5"
	containers := actuary.CreateContainerList(client)
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

func CheckHostNamespace(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.16 Do not share the host's process namespace"
	containers := actuary.CreateContainerList(client)
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

func CheckIPCNamespace(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.17 Do not share the host's IPC namespace"
	containers := actuary.CreateContainerList(client)
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

	return res
}

func CheckHostDevices(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.18 Do not directly expose host devices to containers"
	containers := actuary.CreateContainerList(client)
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

func CheckDefaultUlimit(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "5.19 Override default ulimit at runtime only if needed "
	containers := actuary.CreateContainerList(client)
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
