/*
Package checks - 1. Host Configuration
This section covers security recommendations that you should follow to prepare the host
machine that you plan to use for executing containerized workloads. Securing the Docker
host and following your infrastructure security best practices would build a solid and
secure foundation for executing containerized workloads.
*/
package checks

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/docker/engine-api/client"
	"github.com/drael/GOnetstat"
	version "github.com/hashicorp/go-version"
)

//code borrowed from github.com/dockersecuritytools/batten
func CheckSeparatePartion(client *client.Client) (res Result) {
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
			res.Pass()
			return
		}
	}
	output := "Containers NOT in seperate partition"
	res.Fail(output)
	return
}

func CheckKernelVersion(client *client.Client) (res Result) {
	res.Name = "1.2 Use the updated Linux Kernel"
	info, err := client.Info()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}

	constraints, _ := version.NewConstraint(">= 3.10")
	hostVersion, err := version.NewVersion(info.KernelVersion)
	if err != nil {
		// necessary fix for incompatible kernel versions (e.g. Fedora 23)
		log.Print("Incompatible kernel version")
		output := "Incompatible kernel version reported"
		res.Info(output)
		return
	}
	if constraints.Check(hostVersion) {
		res.Pass()
	} else {
		output := fmt.Sprintf("Host is not using an updated kernel: %s",
			info.KernelVersion)
		res.Fail(output)
	}
	return
}

func CheckRunningServices(client *client.Client) (res Result) {
	var openPorts []int64
	res.Name = "1.5 Remove all non-essential services from the host"
	tcpData := GOnetstat.Tcp()
	for _, proc := range tcpData {
		openPorts = append(openPorts, proc.Port)
	}
	output := fmt.Sprintf("Host listening on %d ports: %d", len(openPorts),
		openPorts)
	res.Info(output)
	return
}

func CheckDockerVersion(client *client.Client) (res Result) {
	res.Name = "1.6 Keep Docker up to date"
	verConstr := os.Getenv("VERSION")
	info, err := client.ServerVersion()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}
	constraints, _ := version.NewConstraint(">= " + verConstr)
	hostVersion, _ := version.NewVersion(info.Version)
	if constraints.Check(hostVersion) {
		res.Pass()
	} else {
		output := fmt.Sprintf("Host is using an outdated Docker server: %s ",
			info.Version)
		res.Fail(output)
	}
	return
}

func CheckTrustedUsers(client *client.Client) (res Result) {
	var trustedUsers []string
	res.Name = "1.7 Only allow trusted users to control Docker daemon"
	groupFile := "/etc/group"
	content, err := ioutil.ReadFile(groupFile)
	if err != nil {
		log.Panicf("Could not read %s", groupFile)
	}
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		fields := strings.Split(line, ":")

		if fields[0] == "docker" {
			if len(fields) > 2 {
				last := fields[len(fields)-1]
				users := strings.Split(last, ",")
				for _, user := range users {
					user = strings.TrimSpace(user)
					if len(user) == 0 {
						continue
					}
					trustedUsers = append(trustedUsers, user)
				}
			}
		}
	}
	output := fmt.Sprintf("The following users control the Docker daemon: %s",
		trustedUsers)
	res.Info(output)

	return
}

func AuditDockerDaemon(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.8 Audit docker daemon"
	ruleExists = checkAuditRule("/usr/bin/docker")

	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}

	return
}

func AuditLibDocker(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.9 Audit Docker files and directories - /var/lib/docker"
	ruleExists = checkAuditRule("/var/lib/docker")

	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}

	return
}

func AuditEtcDocker(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.10 Audit Docker files and directories - /etc/docker"
	ruleExists = checkAuditRule("/etc/docker")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerRegistry(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.11 Audit Docker files and directories - docker-registry.service"
	ruleExists = checkAuditRule("/usr/lib/systemd/system/docker-registry.service")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerService(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.12 Audit Docker files and directories - docker.service "
	ruleExists = checkAuditRule("/var/run/docker.sock")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerSocket(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.13 Audit Docker files and directories - /var/run/docker.sock"
	ruleExists = checkAuditRule("/usr/lib/systemd/system/docker.service")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerSysconfig(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.14 Audit Docker files and directories - /etc/sysconfig/docker"
	ruleExists = checkAuditRule("/etc/sysconfig/docker")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerNetwork(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.15 Audit Docker files and directories - /etc/sysconfig/docker-network"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-network")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerSysRegistry(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.16 Audit Docker files and directories - /etc/sysconfig/docker-registry"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-registry")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerStorage(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.17 Audit Docker files and directories - /etc/sysconfig/docker-storage"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-storage")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}

func AuditDockerDefault(client *client.Client) (res Result) {
	var ruleExists bool
	res.Name = "1.18 Audit Docker files and directories - /etc/default/docker"
	ruleExists = checkAuditRule("/etc/default/docker")
	if ruleExists {
		res.Pass()
	} else {
		res.Fail("")
	}
	return
}
