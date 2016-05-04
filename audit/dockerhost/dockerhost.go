package dockerhost

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"github.com/drael/GOnetstat"
	version "github.com/hashicorp/go-version"
)

var checks = map[string]audit.Check{
	"kernel_version":     CheckKernelVersion,
	"separate_partition": CheckSeparatePartion,
	"running_services":   CheckRunningServices,
	"server_version":     CheckDockerVersion,
	"trusted_users":      CheckTrustedUsers,
	"audit_daemon":       AuditDockerDaemon,
	"audit_lib":          AuditLibDocker,
	"audit_etc":          AuditEtcDocker,
	"audit_registry":     AuditDockerRegistry,
	"audit_service":      AuditDockerService,
	"audit_socket":       AuditDockerSocket,
	"audit_sysconfig":    AuditDockerSysconfig,
	"audit_network":      AuditDockerNetwork,
	"audit_sysregistry":  AuditDockerSysRegistry,
	"audit_storage":      AuditDockerStorage,
	"audit_default":      AuditDockerDefault,
}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
}

//code borrowed from github.com/dockersecuritytools/batten
func CheckSeparatePartion(client *client.Client) audit.Result {
	var res audit.Result
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
			return res
		}
	}

	res.Status = "WARN"
	res.Output = "Containers NOT in seperate partition"
	return res
}

func CheckKernelVersion(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "1.2 Use the updated Linux Kernel"
	info, err := client.Info()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}

	constraints, _ := version.NewConstraint(">= 3.10")
	hostVersion, err := version.NewVersion(info.KernelVersion)
	if err != nil {
		// necessary fix for incompatible kernel versions (e.g. Fedora 23)
		log.Print("incompatible kernel version")
		res.Status = "INFO"
		res.Output = "incompatible kernel version reported"
		return res
	}
	if constraints.Check(hostVersion) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Host is not using an updated kernel: %s",
			info.KernelVersion)
	}

	return res
}

func CheckRunningServices(client *client.Client) audit.Result {
	var openPorts []int64
	var res audit.Result
	res.Name = "1.5 Remove all non-essential services from the host"
	tcpData := GOnetstat.Tcp()
	for _, proc := range tcpData {
		openPorts = append(openPorts, proc.Port)
	}
	res.Status = "INFO"
	res.Output = fmt.Sprintf("Host listening on %d ports: %d", len(openPorts),
		openPorts)
	return res
}

func CheckDockerVersion(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "1.6 Keep Docker up to date"
	verConstr := os.Getenv("VERSION")
	info, err := client.ServerVersion()
	if err != nil {
		log.Fatalf("Could not retrieve info for Docker host")
	}
	constraints, _ := version.NewConstraint(">= " + verConstr)
	hostVersion, _ := version.NewVersion(info.Version)
	if constraints.Check(hostVersion) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Host is using an outdated Docker server: %s ",
			info.Version)
	}

	return res
}

func CheckTrustedUsers(client *client.Client) audit.Result {
	var res audit.Result
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
	res.Status = "INFO"
	res.Output = fmt.Sprintf("The following users control the Docker daemon: %s",
		trustedUsers)

	return res
}

//Helper function to check rules in auditctl
func checkAuditRule(rule string) bool {
	auditctlPath, err := exec.LookPath("auditctl")
	if err != nil || auditctlPath == "" {
		log.Panicf("Could not find auditctl tool")
	}
	cmd := exec.Command(auditctlPath, "-l")
	output, err := cmd.Output()
	if err != nil {
		log.Panicf("Auditctl command returned with errors")
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, rule) {
			return true
		}
	}
	return false
}

func AuditDockerDaemon(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.8 Audit docker daemon"

	ruleExists = checkAuditRule("/usr/bin/docker")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditLibDocker(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.9 Audit Docker files and directories - /var/lib/docker"

	ruleExists = checkAuditRule("/var/lib/docker")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditEtcDocker(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.10 Audit Docker files and directories - /etc/docker"
	ruleExists = checkAuditRule("/etc/docker")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerRegistry(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.11 Audit Docker files and directories - docker-registry.service"
	ruleExists = checkAuditRule("/usr/lib/systemd/system/docker-registry.service")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerService(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.12 Audit Docker files and directories - docker.service "
	ruleExists = checkAuditRule("/var/run/docker.sock")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerSocket(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.13 Audit Docker files and directories - /var/run/docker.sock"
	ruleExists = checkAuditRule("/usr/lib/systemd/system/docker.service")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerSysconfig(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.14 Audit Docker files and directories - /etc/sysconfig/docker"
	ruleExists = checkAuditRule("/etc/sysconfig/docker")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerNetwork(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.15 Audit Docker files and directories - /etc/sysconfig/docker-network"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-network")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerSysRegistry(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.16 Audit Docker files and directories - /etc/sysconfig/docker-registry"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-registry")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerStorage(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.17 Audit Docker files and directories - /etc/sysconfig/docker-storage"
	ruleExists = checkAuditRule("/etc/sysconfig/docker-storage")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}

func AuditDockerDefault(client *client.Client) audit.Result {
	var res audit.Result
	var ruleExists bool
	res.Name = "1.18 Audit Docker files and directories - /etc/default/docker"
	ruleExists = checkAuditRule("/etc/default/docker")

	if ruleExists {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
	}

	return res
}
