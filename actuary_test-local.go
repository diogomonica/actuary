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
	trgt := &Target{}
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, clientHeaders)
	if err != nil {
		t.Errorf("Unable to connect to Docker daemon")
	}
	trgt.Client = cli
	t.Log("Creating container list")
	err = trgt.createContainerList()
	if err != nil {
		t.Errorf("Unable to create container list: %s", err)
	}
	if len(trgt.Containers) != 1 {
		t.Errorf("Expected 1 running container, got %d instead", len(trgt.Containers))
	}
	if trgt.Containers[0].ID != contID {
		t.Errorf("Expected %s, got %s instead", contID, trgt.Containers[0].ID)
	}
}
