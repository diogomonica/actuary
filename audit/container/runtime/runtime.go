package runtime

import (
	"fmt"

	"github.com/diogomonica/actuary"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	// "github.com/docker/engine-api/types/container"
	"log"
	"strconv"
	"strings"
)

var checks = map[string]audit.Check{
	"apparmor_profile":      CheckAppArmor,
	"selinux_options":       CheckSELinux,
	"single_process":        CheckSingleMainProcess,
	"kernel_capabilities":   CheckKernelCapabilities,
	"privileged_containers": CheckPrivContainers,
	"sensitive_dirs":        CheckSensitiveDirs,
	"ssh_running":           CheckSSHRunning,
	"privileged_ports":      CheckPrivilegedPorts,
	"needed_ports":          CheckNeededPorts,
	"host_net_mode":         CheckHostNetworkMode,
	"memory_usage":          CheckMemoryLimits,
	"cpu_shares":            CheckCPUShares,
	"readonly_rootfs":       CheckReadonlyRoot,
	"bind_specific_int":     CheckBindHostInterface,
	"restart_policy":        CheckRestartPolicy,
	"host_namespace":        CheckHostNamespace,
	"ipc_namespace":         CheckIPCNamespace,
	"host_devices":          CheckHostDevices,
	"override_ulimit":       CheckDefaultUlimit,
}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
}

func CheckAppArmor(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
	containers := actuary.CreateContainerList(client)
	if len(containers) != 0 {
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
	} else {
		res.Skip("No running containers")
	}
	return res
}

func CheckSELinux(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.2 Verify SELinux security options, if applicable"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		secOpt := info.HostConfig.SecurityOpt
		if secOpt == nil {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with no SELinux options: %s",
			badContainers)
	}

	return res
}

func CheckSingleMainProcess(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.3 Verify that containers are running only a single main process"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
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
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers running more than one main process: %s",
			badContainers)
	}

	return res
}

func CheckKernelCapabilities(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.4 Restrict Linux Kernel Capabilities within containers"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		kernelCap := info.HostConfig.CapAdd
		if kernelCap != nil {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers running with added kernel capabilities: %s",
			badContainers)
	}

	return res
}

func CheckPrivContainers(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.5 Do not use privileged containers"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		privileged := info.HostConfig.Privileged
		if privileged == true {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Privileged containers found: %s",
			badContainers)
	}

	return res
}

func CheckSensitiveDirs(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.6 Do not mount sensitive host system directories on containers "
	options := types.ContainerListOptions{All: false}
	sensitiveDirs := []string{"/dev", "/etc", "/lib", "/proc", "/sys", "/usr"}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mounts := info.Mounts
		for _, mount := range mounts {
			for _, dir := range sensitiveDirs {
				if strings.HasPrefix(mount.Source, dir) && mount.RW == true {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Sensitive directories mounted on containers: %s",
			badContainers)
	}

	return res
}

func CheckSSHRunning(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.7 Do not run ssh within containers"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
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
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers running SSH service: %s",
			badContainers)
	}

	return res
}

func CheckPrivilegedPorts(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.8 Do not map privileged ports within containers"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		ports := info.NetworkSettings.Ports
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
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with mapped privileged ports: %s",
			badContainers)
	}

	return res
}

func CheckNeededPorts(client *client.Client) audit.Result {
	var res audit.Result
	var containerPort map[string][]string
	containerPort = make(map[string][]string)

	res.Name = "5.9 Open only needed ports on container"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}

	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		ports := info.NetworkSettings.Ports
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

func CheckHostNetworkMode(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.10 Do not use host network mode on container"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mode := info.HostConfig.NetworkMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Privileged containers found: %s",
			badContainers)
	}

	return res
}

func CheckMemoryLimits(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.11 Limit memory usage for container"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mem := info.HostConfig.Memory
		if mem == 0 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with no memory limits: %s",
			badContainers)
	}

	return res
}

func CheckCPUShares(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.12 Set container CPU priority appropriately"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		shares := info.HostConfig.CPUShares
		if shares == 0 || shares == 1024 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with CPU sharing disabled: %s",
			badContainers)
	}

	return res
}

func CheckReadonlyRoot(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.13 Mount container's root filesystem as read only"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		readonly := info.HostConfig.ReadonlyRootfs
		if readonly == false {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers' root FS is not mounted as read-only: %s",
			badContainers)
	}

	return res
}

func CheckBindHostInterface(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.14 Bind incoming container traffic to a specific host interface"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		ports := info.NetworkSettings.Ports
		for _, port := range ports {
			for _, portmap := range port {
				if portmap.HostIP == "0.0.0.0" {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers traffic not bound to specific host interface: %s",
			badContainers)
	}

	return res
}

func CheckRestartPolicy(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.15 Set the 'on-failure' container restart policy to 5"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		policy := info.HostConfig.RestartPolicy
		if policy.Name != "on-failure" && policy.MaximumRetryCount < 5 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with no restart policy: %s",
			badContainers)
	}

	return res
}

func CheckHostNamespace(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.16 Do not share the host's process namespace"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mode := info.HostConfig.PidMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers sharing host's process namespace: %s",
			badContainers)
	}

	return res
}

func CheckIPCNamespace(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.17 Do not share the host's IPC namespace"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		mode := info.HostConfig.IpcMode
		if mode == "host" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers sharing host's IPC namespace: %s",
			badContainers)
	}

	return res
}

func CheckHostDevices(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.18 Do not directly expose host devices to containers"
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		devices := info.HostConfig.Devices
		if len(devices) != 0 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Host devices exposed. Check your permissions: %s",
			badContainers)
	}

	return res
}

func CheckDefaultUlimit(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.19 Override default ulimit at runtime only if needed "
	options := types.ContainerListOptions{All: false}
	containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}
	if len(containers) == 0 {
		res.Status = "INFO"
		res.Output = "No running containers"
		return res
	}

	for _, container := range containers {
		info, _ := client.ContainerInspect(container.ID)
		ulimit := info.HostConfig.Ulimits
		if ulimit != nil {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers overriding default ulimit: %s",
			badContainers)
	}

	return res
}
