/*
Package checks - 4 Container Images and Build File
Container base images and build files govern the fundamentals of how a container instance
from a particular image would behave. Ensuring that you are using proper base images and
appropriate build files can be very important for building your containerized
infrastructure. Below are some of the recommendations that you should follow for
container base images and build files to ensure that your containerized infrastructure is
secure.
*/
package actuary

import (
	"fmt"
	"os"
)


//Global variables for testing
var trust string = os.Getenv("DOCKER_CONTENT_TRUST")

func CheckContainerUser(t Target) (res Result) {
	var rootContainers []string
	res.Name = "4.1 Create a user for the container"
	containers := t.Containers
	if !containers.Running() {
		res.Skip("No running containers")
		return
	}
	for _, container := range containers {
		user := container.Info.Config.User
		if user == "" {
			rootContainers = append(rootContainers, container.ID)
		}
	}

	if len(rootContainers) == 0 {
		res.Pass()
	} else {
		output := fmt.Sprintf("Containers running as root: %s", rootContainers)
		res.Fail(output)
	}
	return res
}

func CheckContentTrust(t Target) (res Result) {
	res.Name = "4.5 Enable Content trust for Docker"

	//trust := os.Getenv("DOCKER_CONTENT_TRUST")

	//log.Printf("TRUST: %s", trust)

	if trust == "1" {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}
