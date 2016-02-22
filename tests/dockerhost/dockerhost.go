package dockerhost

import (
	"fmt"
	"io/ioutil"
	"strings"
	"github.com/docker/engine-api/client"
  //  "github.com/docker/engine-api/types"

)

type Check func(client *client.Client)

var checks = map[string]Check{
	"kernel_version":     CheckKernelVersion,
	"seperate_partition": CheckSeperatePartion,
}

func GetAuditDefinitions() map[string]Check {

	return checks
}

//1.1 Create a separate partition for containers
//code borrowed from github.com/dockersecuritytools/batten
func CheckSeperatePartion(client *client.Client) {
	fstab := "/etc/fstab"
	bytes, err := ioutil.ReadFile(fstab)

	if err != nil {
		fmt.Println("Cannor read fstab")
		return
	}

	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) > 1 && fields[1] == "/var/lib/docker" {
			fmt.Println("Containers in seperate partition")
			return
		}
	}

	fmt.Println("Containers NOT in seperate partition")
}


func CheckKernelVersion(client *client.Client) {
	info, _ := client.Info()
	fmt.Println(info.KernelVersion)

}



