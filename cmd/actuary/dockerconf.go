/*
Package checks  - 2 Docker daemon configuration
This section lists the recommendations that alter and secure the behavior of Docker
daemon (server). The settings that are under this section affect ALL container instances.
*/
package actuary

import (
	"fmt"
	"strings"
	//"log"

	"golang.org/x/net/context"
	"github.com/docker/docker/api/types"
)

//Global variables for testing
var procFunction = getProcCmdline

func RestrictNetTraffic(t Target) (res Result) {
	var netargs types.NetworkListOptions
	res.Name = "2.1 Restrict network traffic between containers"
	networks, err := t.Client.NetworkList(context.TODO(), netargs)
	//log.Printf("%v", networks[0])
	//log.Printf("network list: %s", networks)
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

func CheckLoggingLevel(t Target) (res Result) {

	res.Name = "2.2 Set the logging level"
	cmdLine, _ := procFunction("docker")
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

func CheckIpTables(t Target) (res Result) {
	res.Name = "2.3 Allow Docker to make changes to iptables"
	cmdLine, _ := procFunction("docker")
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

func CheckInsecureRegistry(t Target) (res Result) {
	res.Name = "2.4 Do not use insecure registries"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--insecure-registry") {
			res.Status = "WARN"
			return
		}
	}
	res.Pass()
	return
}

func CheckAufsDriver(t Target) (res Result) {
	res.Name = "2.5 Do not use the aufs storage driver"
	info := t.Info
	storageDriver := info.Driver

	if storageDriver == "aufs" {
		res.Fail("")
	} else {
		res.Pass()
	}
	return
}

func CheckTLSAuth(t Target) (res Result) {
	res.Name = "2.6 Configure TLS authentication for Docker daemon"
	tlsOpts := []string{"--tlsverify", "--tlscacert", "--tlscert", "--tlskey"}
	cmdLine, _ := procFunction("docker")
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

func CheckUlimit(t Target) (res Result) {
	res.Name = "2.7 Set default ulimit as appropriate"
	cmdLine, _ := procFunction("docker")
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

func CheckUserNamespace(t Target) (res Result) {
	res.Name = "2.8 Enable user namespace support"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--userns-remap") {
			res.Pass()
			return
		}
	}
	output := "User namespace support is not enabled"
	res.Fail(output)
	return res
}

func CheckDefaultCgroup(t Target) (res Result) {
	res.Name = "2.9 Confirm default cgroup usage"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--cgroup-parent") {
			res.Pass()
			return
		}
	}
	output := "Default cgroup is not used"
	res.Fail(output)
	return res
}

func CheckBaseDevice(t Target) (res Result) {
	res.Name = "2.10 Do not change base device size until needed"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--storage-opt dm.basesize") {
			res.Pass()
			return
		}
	}
	output := "Default device size has been changed"
	res.Fail(output)
	return res
}

func CheckAuthPlugin(t Target) (res Result) {
	res.Name = "2.11 Use authorization plugin"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--authorization-plugin") {
			res.Pass()
			return
		}
	}
	res.Fail("")
	return res
}

func CheckCentralLogging(t Target) (res Result) {
	res.Name = "2.12 Configure centralized and remote logging"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--log-driver") {
			res.Pass()
			return
		}
	}
	res.Fail("")
	return res
}

func CheckLegacyRegistry(t Target) (res Result) {
	res.Name = "2.13 Disable operations on legacy registry (v1)"
	cmdLine, _ := procFunction("docker")
	for _, arg := range cmdLine {
		if strings.Contains(arg, "--disable-legacy-registry") {
			res.Pass()
			return
		}
	}
	res.Fail("")
	return res
}
