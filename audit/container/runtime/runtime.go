package runtime

import (
	"fmt"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	// "github.com/docker/engine-api/types/container"
	"log"
	"strings"
	"strconv"
)

var checks = map[string]audit.Check{
	"apparmor_profile": CheckAppArmor,
	"selinux_options": CheckSELinux,
	"single_process": CheckSingleMainProcess,
	"kernel_capabilities": CheckKernelCapabilities,
	"privileged_containers": CheckPrivContainers,
	"sensitive_dirs": CheckSensitiveDirs,
	"ssh_running": CheckSshRunning,
	"privileged_ports": CheckPrivilegedPorts,
	"needed_ports": CheckNeededPorts,


}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
}


func CheckAppArmor(client *client.Client) audit.Result {
	var res audit.Result
	var badContainers []string
	res.Name = "5.1 Verify AppArmor Profile, if applicable"
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
		info, err := client.ContainerInspect(container.ID)
		if err != nil {
			log.Printf("Could not inspect container with ID: %s", container.ID)
			continue
		}
		user := info.AppArmorProfile
		if user == "" {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with no AppArmor profile: %s", badContainers)
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
		res.Output = fmt.Sprintf("Containers with no SELinux options: %s", badContainers)
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
		for _, proc :=range procs.Processes[1:] {
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
		res.Output = fmt.Sprintf("Containers running more than one main process: %s", badContainers)
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
		res.Output = fmt.Sprintf("Containers running with added kernel capabilities: %s", badContainers)
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
		res.Output = fmt.Sprintf("Privileged containers found: %s", badContainers)
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
				if strings.HasPrefix(mount.Source,dir) && mount.RW == true {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Sensitive directories mounted on containers: %s", badContainers)
	}

	return res
}

func CheckSshRunning(client *client.Client) audit.Result {
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
		for _, proc :=range procs.Processes {
			procname := proc[7]
			if strings.Contains(procname,"ssh") {
				badContainers = append(badContainers, container.ID)
			}
		}
	}
	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers running SSH service: %s", badContainers)
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
				if  hostPort < 1024 {
					badContainers = append(badContainers, container.ID)
				}
			}
		}
	}

	if len(badContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers with mapped privileged ports: %s", badContainers)
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
			containerPort[container.ID] = append(containerPort[container.ID], string(key))
		}
	}
		res.Status = "INFO"
		res.Output = fmt.Sprintf("Containers with mapped privileged ports: %v \n", containerPort)

	return res
}