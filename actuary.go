package actuary

import (
	"log"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/strslice"
)

type ContainerInfo struct {
	types.ContainerJSON
}

type Container struct {
	ID   string
	Info ContainerInfo
}

type ContainerList []Container

func (c *ContainerInfo) AppArmor() string {
	return c.AppArmorProfile
}

func (c *ContainerInfo) SELinux() []string {
	return c.HostConfig.SecurityOpt
}

func (c *ContainerInfo) KernelCapabilities() *strslice.StrSlice {
	return c.HostConfig.CapAdd
}

func (c *ContainerInfo) Privileged() bool {
	return c.HostConfig.Privileged
}

func (l *ContainerList) Running() bool {
	if len(*l) != 0 {
		return true
	}
	return false
}

func CreateContainerList(c *client.Client) (l ContainerList) {
	opts := types.ContainerListOptions{All: false}
	containers, err := c.ContainerList(opts)
	if err != nil {
		log.Fatalf("Unable to get container list")
	}
	for _, cont := range containers {
		entry := new(Container)
		inspectData, _ := c.ContainerInspect(cont.ID)
		info := &ContainerInfo{inspectData}
		entry.ID = cont.ID
		entry.Info = *info
		l = append(l, *entry)
	}
	return
}
