/*
Package checks  - 2 Docker daemon configuration
This section lists the recommendations that alter and secure the behavior of Docker
daemon (server). The settings that are under this section affect ALL container instances.
*/
package checks

import (
	"fmt"
	"strings"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
)

func CheckLxcDriver(client *client.Client) (res Result) {
	res.Name = "2.1 Do not use lxc execution driver"
	info, err := client.Info()
	if err != nil {
		res.Skip("Unable to connect to Docker daemon")
		return
	}
	execDriver := info.ExecutionDriver

	if strings.Contains(execDriver, "lxc") {
		res.Status = "WARN"
	} else {
		res.Pass()
	}
	return
}

func RestrictNetTraffic(client *client.Client) (res Result) {
	var netargs types.NetworkListOptions
	res.Name = "2.2 Restrict network traffic between containers"

	networks, err := client.NetworkList(netargs)
	if err != nil {
		res.Skip("Cannot retrieve network list")
		return
	}
	for _, network := range networks {
		if network.Name == "bridge" {
			if network.Options["com.docker.network.bridge.enable_icc"] == "true" {
				res.Status = "WARN"
				return
			}
		}
	}
	res.Pass()
	return
}

func CheckLoggingLevel(client *client.Client) (res Result) {
	res.Name = "2.3 Set the logging level"

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--log-level") {
			level := strings.Trim(strings.Split(arg, "=")[1], "\"")
			if level != "info" {
				output := "Docker daemon log level should be set to \"info\""
				res.Fail(output)
				return
			}
		}
	}
	res.Pass()
	return
}

func CheckIpTables(client *client.Client) (res Result) {
	res.Name = "2.4 Allow Docker to make changes to iptables"

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--iptables") {
			val := strings.Trim(strings.Split(arg, "=")[1], "\"")
			if val != "false" {
				res.Status = "WARN"
				return res
			}
		}
	}
	res.Pass()
	return
}

func CheckInsecureRegistry(client *client.Client) (res Result) {
	res.Name = "2.5 Do not use insecure registries"

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--insecure-registry") {
			res.Status = "WARN"
			return
		}
	}
	res.Pass()
	return
}

func CheckLocalRegistry(client *client.Client) (res Result) {
	res.Name = "2.6 Setup a local registry mirror"

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--registry-mirror") {
			res.Pass()
			return
		}
	}
	res.Status = "WARN"
	return res
}

func CheckAufsDriver(client *client.Client) (res Result) {
	res.Name = "2.7 Do not use the aufs storage driver"
	info, err := client.Info()
	if err != nil {
		res.Skip("Unable to connect to Docker daemon")
		return
	}
	storageDriver := info.Driver

	if storageDriver == "aufs" {
		res.Status = "WARN"
	} else {
		res.Pass()
	}
	return
}

func CheckDefaultSocket(client *client.Client) (res Result) {
	res.Name = "2.8 Do not bind Docker to another IP/Port or a Unix socket "

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "-H") {
			res.Status = "WARN"
			return
		}
	}
	res.Pass()
	return
}

func CheckTLSAuth(client *client.Client) (res Result) {
	res.Name = "2.9 Configure TLS authentication for Docker daemon"
	tlsOpts := []string{"--tlsverify", "--tlscacert", "--tlscert", "--tlskey"}

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		for i, tlsOpt := range tlsOpts {
			if strings.Contains(arg, tlsOpt) {
				tlsOpts = append(tlsOpts[:i], tlsOpts[i+1:]...)
			}
		}
	}

	if len(tlsOpts) != 0 {
		output := fmt.Sprintf("TLS configuration is missing options: %s", tlsOpts)
		res.Fail(output)
		return
	}
	res.Pass()
	return
}

func CheckUlimit(client *client.Client) (res Result) {
	res.Name = "2.10 Set default ulimit as appropriate"

	cmdLine, _ := GetProcCmdline("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--default-ulimit") {
			res.Pass()
			return
		}
	}
	output := "Default ulimit doesn't appear to be set"
	res.Fail(output)
	return res
}
