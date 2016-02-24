package dockerhost

import (
	"fmt"
	"github.com/docker/engine-api/client"
	"github.com/drael/GOnetstat"
	version "github.com/hashicorp/go-version"
	"io/ioutil"
	"log"
	"strings"
	"os"
	//  "github.com/docker/engine-api/types"
)

// Struct for returning the result of each check. Status value can be
// PASS, WARN or INFO
type Result struct {
	Name   string
	Status string
	Output string
}

type Check func(client *client.Client) Result

var checks = map[string]Check{
	"kernel_version":     CheckKernelVersion,
	"seperate_partition": CheckSeperatePartion,
	"running_services":   CheckRunningServices,
	"server_version":     CheckDockerVersion,
}

func GetAuditDefinitions() map[string]Check {

	return checks
}

//1.1 Create a separate partition for containers
//code borrowed from github.com/dockersecuritytools/batten
func CheckSeperatePartion(client *client.Client) Result {
	var res Result
	res.Name = "1.1 Create a separate partition for containers"
	fstab := "/etc/fstab"
	bytes, err := ioutil.ReadFile(fstab)

	if err != nil {
		log.Printf("Cannor read fstab")
		return res
	}

	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) > 1 && fields[1] == "/var/lib/docker" {
			res.Status = "PASS"
			res.Output = "Containers in seperate partition"
			return res
		}
	}

	res.Status = "WARN"
	res.Output = "Containers NOT in seperate partition"
	return res
}

// 1.2 Use the updated Linux Kernel
func CheckKernelVersion(client *client.Client) Result {
	var res Result
	res.Name = "1.2 Use the updated Linux Kernel"
	info, err := client.Info()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}

	constraints, _ := version.NewConstraint(">= 3.10")
	hostVersion, _ := version.NewVersion(info.KernelVersion)
	if constraints.Check(hostVersion) {
		res.Status = "PASS"
		res.Output = "Host is using an updated kernel"
	} else {
		res.Status = "WARN"
		res.Output = "Host is not using an updated kernel: " + info.KernelVersion
	}

	return res
}

func CheckRunningServices(client *client.Client) Result {
	var openPorts []int64
	var res Result
	res.Name = "1.5 Remove all non-essential services from the host"
	tcpData := GOnetstat.Tcp()
	for _, proc := range tcpData {
		openPorts = append(openPorts, proc.Port)
	}
	res.Status = "INFO"
	res.Output = fmt.Sprintf("Host listening on %d ports: %d", len(openPorts), openPorts)
	return res
}

func CheckDockerVersion(client *client.Client) Result {
	var res Result
	res.Name = "1.6 Keep Docker up to date"
	verConstr := os.Getenv("VERSION")
	info, err := client.ServerVersion()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}
	constraints, _ := version.NewConstraint(">= "+ verConstr)
	hostVersion, _ := version.NewVersion(info.Version)
	if constraints.Check(hostVersion) {
		res.Status = "PASS"
		res.Output = "Host is using an updated Docker Server: " + info.Version
	} else {
		res.Status = "WARN"
		res.Output = "Host is using an outdated Docker server: " + info.Version
	}

	return res
}

// func CheckTrustedUsers(client *client.Client) Result {
// 	var res Result
// 	res.Name = "1.7 Only allow trusted users to control Docker daemon"
// }
