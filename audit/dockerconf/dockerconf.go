package dockerconf

import (
	"fmt"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"log"
	"strings"
	//"os"
)

var checks = map[string]audit.Check{
	"lxc_driver":        CheckLxcDriver,
	"net_traffic":       RestrictNetTraffic,
	"logging_level":     CheckLoggingLevel,
	"allow_iptables":    CheckIpTables,
	"insecure_registry": CheckInsecureRegistry,
	"local_registry":    CheckLocalRegistry,
	"aufs_driver":       CheckAufsDriver,
	"default_socket":    CheckDefaultSocket,
	"tls_auth":          CheckTLSAuth,
	"default_ulimit":    CheckUlimit,
}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
}

func CheckLxcDriver(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.1 Do not use lxc execution driver"
	info, err := client.Info()
	if err != nil {
		log.Printf("Unable to connect to Docker daemon")
	}
	execDriver := info.ExecutionDriver

	if strings.Contains(execDriver, "lxc") {
		res.Status = "WARN"
	} else {
		res.Status = "PASS"
	}
	return res
}

func RestrictNetTraffic(client *client.Client) audit.Result {
	var res audit.Result
	var netargs types.NetworkListOptions
	res.Name = "2.2 Restrict network traffic between containers"

	networks, err := client.NetworkList(netargs)
	if err != nil {
		log.Printf("Cannot retrieve network list")
		return res
	}
	for _, network := range networks {
		if network.Name == "bridge" {
			if network.Options["com.docker.network.bridge.enable_icc"] == "true" {
				res.Status = "WARN"
				return res
			}
		}
	}
	res.Status = "PASS"
	return res
}

func CheckLoggingLevel(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.3 Set the logging level"

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--log-level") {
			level := strings.Trim(strings.Split(arg, "=")[1], "\"")
			if level != "info" {
				res.Status = "WARN"
				res.Output = "Docker daemon log level should be set to \"info\""
				return res
			}
		}
	}
	res.Status = "PASS"
	return res
}

func CheckIpTables(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.4 Allow Docker to make changes to iptables"

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--iptables") {
			val := strings.Trim(strings.Split(arg, "=")[1], "\"")
			if val != "false" {
				res.Status = "WARN"
				return res
			}
		}
	}
	res.Status = "PASS"
	return res
}

func CheckInsecureRegistry(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.5 Do not use insecure registries"

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--insecure-registry") {
			res.Status = "WARN"
			return res
		}
	}
	res.Status = "PASS"
	return res
}

func CheckLocalRegistry(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.6 Setup a local registry mirror"

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "'--registry-mirror") {
			res.Status = "PASS"
			return res
		}
	}
	res.Status = "WARN"
	return res
}

func CheckAufsDriver(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.7 Do not use the aufs storage driver"
	info, err := client.Info()
	if err != nil {
		log.Printf("Unable to connect to Docker daemon")
	}
	storageDriver := info.Driver

	if storageDriver == "aufs" {
		res.Status = "WARN"
	} else {
		res.Status = "PASS"
	}
	return res
}

func CheckDefaultSocket(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.8 Do not bind Docker to another IP/Port or a Unix socket "

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "'-H") {
			res.Status = "WARN"
			return res
		}
	}
	res.Status = "PASS"
	return res
}

func CheckTLSAuth(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.9 Configure TLS authentication for Docker daemon"
	tlsOpts := []string{"--tlsverify", "--tlscacert", "--tlscert", "--tlskey"}

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		for i, tlsOpt := range tlsOpts {
			if strings.Contains(arg, tlsOpt) {
				tlsOpts = append(tlsOpts[:i], tlsOpts[i+1:]...)
			}
		}
	}

	if len(tlsOpts) != 0 {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("TLS configuration is missing options: %s", tlsOpts)
		return res
	}
	res.Status = "PASS"
	return res
}

func CheckUlimit(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "2.10 Set default ulimit as appropriate"

	cmdLine, _ := audit.GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "'--default-ulimit") {
			res.Status = "PASS"
			return res
		}
	}
	res.Status = "WARN"
	res.Output = "Default ulimit doesn't appear to be set"
	return res
}
