package actuary


import (
	//"os"\
	//"fmt"

	//"encoding/json"
	//"log"
	//"io/ioutil"
	"testing"
	//"strconv"
	//"io"
	//"net/http" //Package http provides HTTP client and server implementations.
	//"net/http/httptest" //Package httptest provides utilities for HTTP testing.
	//"github.com/docker/engine-api/types"
	//"github.com/docker/go-connections/nat"	
	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	//"github.com/docker/docker/api"
	//"github.com/gorilla/mux"
	//"github.com/diogomonica/actuary/actuary"


)

//4. Container Images and Build File

func TestCheckContainerUser(t *testing.T) {
	//all containers should have a not blank user?
	t.Log("Setting all container users")

	containers := testTarget.Containers

	//t.Log("XXXXXXX %i", len(testTarget.Containers))

	for _, container := range containers {
		container.Info.Config.User = "x"
	}

	res := CheckContainerUser(testTarget)

	if  res.Status != "PASS" {
		t.Errorf("All users checked, should have passed." )
	}
}

func TestCheckContentTrust(t *testing.T) {
	//Question about os.GetEnv -- doesn't seem to work?

	trust = "1"

	for i := 0; i< 2; i++{

		res := CheckContentTrust(testTarget)

		if  i == 0 && res.Status != "PASS" {
			t.Errorf("Content trust for Docker enabled, should have passed." )
		}

		if  i == 1 && res.Status == "PASS" {
			t.Errorf("Content trust for Docker disabled, should not have passed." )
		}

		trust = ""
	}

}