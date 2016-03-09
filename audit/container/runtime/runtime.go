package runtime

import (
	"fmt"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	// "github.com/docker/engine-api/types/container"
	"log"
)

var checks = map[string]audit.Check{
	"apparmor_profile": CheckAppArmor,
	"selinux_options": CheckSELinux,
	"single_process": CheckSingleMainProcess,
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