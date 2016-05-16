/* This test suite should NOT run on CircleCI due to elevated privilege
requirements. You should run this on a local machine with full access
to a Docker server*/

package actuary

import (
	"testing"

	"github.com/docker/engine-api/client"
)

//WARNING: Change this value to a running container ID before running tests
const contID = ""

var clientHeaders map[string]string

func TestCreateContainerList(t *testing.T) {
	clientHeaders = make(map[string]string)
	clientHeaders["User-Agent"] = "engine-api-cli-1.0"
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, clientHeaders)
	if err != nil {
		t.Errorf("Unable to connect to Docker daemon")
	}
	t.Log("Creating container list")
	containers := CreateContainerList(cli)
	if len(containers) != 1 {
		t.Errorf("Expected 1 running container, got %d instead", len(containers))
	}
	if containers[0].ID != contID {
		t.Errorf("Expected %s, got %s instead", contID, containers[0].ID)
	}
}
