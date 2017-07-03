/*
Package checks - 1. Host Configuration
This section covers security recommendations that you should follow to prepare the host
machine that you plan to use for executing containerized workloads. Securing the Docker
host and following your infrastructure security best practices would build a solid and
secure foundation for executing containerized workloads.
*/
package actuary

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/net/context"

	"github.com/drael/GOnetstat"
	version "github.com/hashicorp/go-version"
)
// Notes:
	//Global variable def
	//can look at unexported fields in test.go
	//before start test, change variable
	//directory called testdata
	//testdata/whatever

//GLOBAL VARIABLES:
	var(
		fstab = "/etc/fstab"
		groupFile = "/etc/group"
	)
//code borrowed from github.com/dockersecuritytools/batten
func  CheckSeparatePartition(t Target) (res Result) {
	res.Name = "1.1 Create a separate partition for containers"
	//fstab := "/etc/fstab" 
	

	bytes, err := ioutil.ReadFile(fstab)

	if err != nil {
		log.Printf("Cannot read fstab")
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

func CheckKernelVersion(t Target) (res Result) {
	res.Name = "1.2 Use the updated Linux Kernel"
	info := t.Info
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

func CheckRunningServices(t Target) (res Result) {
	var openPorts []int64
	res.Name = "1.4 Remove all non-essential services from the host"
	tcpData := GOnetstat.Tcp()
	for _, proc := range tcpData {
		openPorts = append(openPorts, proc.Port)
	}
	output := fmt.Sprintf("Host listening on %d ports: %d", len(openPorts),
		openPorts)
	res.Info(output)
	return
}

func CheckDockerVersion(t Target) (res Result) {
	res.Name = "1.5 Keep Docker up to date"
	verConstr := os.Getenv("VERSION")
	
	if len(verConstr) == 0 {
        verConstr = "17.03"
    }

	info, err := t.Client.ServerVersion(context.TODO())
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

func CheckTrustedUsers(t Target) (res Result) {
	var trustedUsers []string
	res.Name = "1.6 Only allow trusted users to control Docker daemon"
	//groupFile := "/etc/group"
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

func AuditDockerDaemon(t Target) (res Result) {
	res.Name = "1.7 Audit docker daemon"
	err := checkAuditRule("/usr/bin/docker")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditLibDocker(t Target) (res Result) {
	res.Name = "1.8 Audit Docker files and directories - /var/lib/docker"
	err := checkAuditRule("/var/lib/docker")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditEtcDocker(t Target) (res Result) {
	res.Name = "1.9 Audit Docker files and directories - /etc/docker"
	err := checkAuditRule("/etc/docker")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditDockerService(t Target) (res Result) {
	res.Name = "1.10 Audit Docker files and directories - docker.service"
	err := checkAuditRule("/usr/lib/systemd/system/docker.service")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditDockerSocket(t Target) (res Result) {
	res.Name = "1.11 Audit Docker files and directories - docker.socket"
	err := checkAuditRule("/usr/lib/systemd/system/docker.socket")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditDockerDefault(t Target) (res Result) {
	res.Name = "1.12 Audit Docker files and directories - /etc/default/docker"
	err := checkAuditRule("/etc/default/docker")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditDaemonJSON(t Target) (res Result) {
	res.Name = "1.13 Audit Docker files and directories - /etc/docker/daemon.json"
	err := checkAuditRule("/etc/docker/daemon.json")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditContainerd(t Target) (res Result) {
	res.Name = "1.14 Audit Docker files and directories - /usr/bin/docker-containerd"
	err := checkAuditRule("/usr/bin/docker-containerd")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}

func AuditRunc(t Target) (res Result) {
	res.Name = "1.15 Audit Docker files and directories - /usr/bin/docker-runc"
	err := checkAuditRule("/usr/bin/docker-runc")
	if err == nil {
		defer res.Pass()
	} else if err.Code == 1 {
		defer res.Skip(err.Message)
	} else {
		defer res.Fail("")
	}
	return
}
