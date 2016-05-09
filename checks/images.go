/*
Package checks - 4 Container Images and Build File
Container base images and build files govern the fundamentals of how a container instance
from a particular image would behave. Ensuring that you are using proper base images and
appropriate build files can be very important for building your containerized
infrastructure. Below are some of the recommendations that you should follow for
container base images and build files to ensure that your containerized infrastructure is
secure.
*/
package checks

import (
	"fmt"
	"log"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
)

func CheckContainerUser(client *client.Client) (res Result) {
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
