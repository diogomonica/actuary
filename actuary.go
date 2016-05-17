package actuary

import (
	"fmt"
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

type Target struct {
	Client     *client.Client
	Info       types.Info
	Containers ContainerList
}

func NewTarget() (a Target, err error) {
	a.Client, err = client.NewEnvClient()
	if err != nil {
		fmt.Printf("Unable to create Docker client")
		return
	}
	a.Info, err = a.Client.Info()
	if err != nil {
		fmt.Printf("Unable to create Docker client")
		return
	}
	err = a.createContainerList()
	return
}

func (t *Target) createContainerList() error {
	opts := types.ContainerListOptions{All: false}
	containers, err := t.Client.ContainerList(opts)
	if err != nil {
		log.Fatalf("Unable to get container list")
	}
	for _, cont := range containers {
		entry := new(Container)
		inspectData, _ := t.Client.ContainerInspect(cont.ID)
		info := &ContainerInfo{inspectData}
		entry.ID = cont.ID
		entry.Info = *info
		t.Containers = append(t.Containers, *entry)
	}
	return nil
}
