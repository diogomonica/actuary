package dockerconf


import (
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"log"
	"strings"
	"github.com/docker/engine-api/types"
)


var checks = map[string]audit.Check{
	"lxc_driver":     CheckLxcDriver,
	"net_traffic":	RestrictNetTraffic,
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
