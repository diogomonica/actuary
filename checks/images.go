package checks

import (
	"fmt"
	"log"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
)

var checks = map[string]checks.Check{
	"root_containers": CheckContainerUser,
}

func GetAuditDefinitions() map[string]checks.Check {

	return checks
}

func CheckContainerUser(client *client.Client) (res checks.Result) {
	var rootContainers []string
	res.Name = "4.1 Create a user for the container"
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
		user := info.Config.User
		if user == "" {
			rootContainers = append(rootContainers, container.ID)
		}
	}

	if len(rootContainers) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Containers running as root: %s", rootContainers)
	}

	return res
}
