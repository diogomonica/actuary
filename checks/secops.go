/*
Package checks - 6 Docker Security Operations
This sections covers some of the operational security aspects for Docker deployments.
These are best practices that should be followed. Most of the recommendations here are
just reminders that organizations should extend their current security best practices and
policies to include containers.
*/
package checks

import (
	"fmt"
	"log"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
)

func CheckCentralLogging(client *client.Client) (res Result) {
	var badContainers []string
	res.Name = "6.5 Use a centralized and remote log collection service"
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
		mounts := info.Mounts
		if len(mounts) == 0 {
			badContainers = append(badContainers, container.ID)
		}
	}

	if len(badContainers) == 0 {
		res.Status = "INFO"
		res.Output = `Volumes found in all containers.Ensure centralized
		logging is enabled`
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf(`Containers have no volumes, ensure centralized
		 logging is enabled : %s`, badContainers)
	}

	return res
}

func CheckContainerSprawl(client *client.Client) (res Result) {
	var diff int
	res.Name = "6.7 Avoid container sprawl"
	options := types.ContainerListOptions{All: false}
	run_containers, err := client.ContainerList(options)
	options = types.ContainerListOptions{All: true}
	all_containers, err := client.ContainerList(options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}

	diff = len(all_containers) - len(run_containers)

	if diff > 25 {
		res.Status = "WARN"
		res.Output = fmt.Sprintf(`There are currently a total of %d containers,
			with only %d of them currently running`, len(all_containers),
			len(run_containers))
	} else {
		res.Status = "PASS"
		res.Output = fmt.Sprintf(`There are currently a total of %d containers,
			with only %d of them currently running`, len(all_containers),
			len(run_containers))

	}
	return res
}
