/*
Package checks - 6 Docker Security Operations
This sections covers some of the operational security aspects for Docker deployments.
These are best practices that should be followed. Most of the recommendations here are
just reminders that organizations should extend their current security best practices and
policies to include containers.
*/
package actuary

import (
	"fmt"
	"log"

	"golang.org/x/net/context"

	"github.com/docker/docker/api/types"
)

func CheckImageSprawl(t Target) (res Result) {
	var allImageIDs []string
	var runImageIDs []string
	res.Name = "6.4 Avoid image sprawl"
	imgOpts := types.ImageListOptions{All: false}
	allImages, err := t.Client.ImageList(context.TODO(), imgOpts)
	if err != nil {
		res.Skip("Unable to retrieve image list")
		return
	}
	for _, image := range allImages {
		allImageIDs = append(allImageIDs, image.ID)
	}

	conOpts := types.ContainerListOptions{All: true}
	containers, err := t.Client.ContainerList(context.TODO(), conOpts)
	if err != nil {
		res.Skip("Unable to retrieve container list")
		return
	}

	for _, container := range containers {
		runImageIDs = append(runImageIDs, container.ImageID)
	}
	if len(allImageIDs) > 100 {
		output := fmt.Sprintf(`There are currently %d images`, len(allImageIDs))
		res.Fail(output)
	} else if len(runImageIDs) < (len(allImageIDs) / 2) {
		output := fmt.Sprintf(`Only %d out of %d images are in use.`,
			len(allImageIDs), len(runImageIDs))
		res.Fail(output)
	} else {
		res.Pass()
	}
	return
}

func CheckContainerSprawl(t Target) (res Result) {
	var diff int
	res.Name = "6.5 Avoid container sprawl"
	options := types.ContainerListOptions{All: false}
	runContainers, err := t.Client.ContainerList(context.TODO(), options)
	options = types.ContainerListOptions{All: true}
	allContainers, err := t.Client.ContainerList(context.TODO(), options)
	if err != nil {
		log.Printf("Unable to get container list")
		return res
	}

	diff = len(allContainers) - len(runContainers)

	if diff > 25 {
		output := fmt.Sprintf(`There are currently a total of %d containers,
			with only %d of them currently running`, len(allContainers),
			len(runContainers))
		res.Fail(output)
	} else {
		res.Pass()
	}
	return
}
