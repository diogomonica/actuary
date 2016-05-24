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

//Target stores information regarding the audit's target Docker server
type Target struct {
	Client     *client.Client
	Info       types.Info
	Containers ContainerList
}

//NewTarget initiates a new Target struct
func NewTarget() (a Target, err error) {
	a.Client, err = client.NewEnvClient()
	if err != nil {
		log.Fatalf("unable to create Docker client: %v\n", err)
	}
	a.Info, err = a.Client.Info()
	if err != nil {
		log.Fatalf("unable to fetch Docker daemon info: %v\n", err)
	}
	err = a.createContainerList()
	return
}

func (t *Target) createContainerList() error {
	opts := types.ContainerListOptions{All: false}
	containers, err := t.Client.ContainerList(opts)
	if err != nil {
		log.Fatalf("unable to get container list: %v\n", err)
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
