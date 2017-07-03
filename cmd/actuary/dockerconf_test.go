package actuary


import (
	//"os"\
	//"fmt"

	"encoding/json"
	//"log"
	//"io/ioutil"
	"testing"
	//"strconv"
	//"io"
	//"net/http" //Package http provides HTTP client and server implementations.
	//"net/http/httptest" //Package httptest provides utilities for HTTP testing.
	"github.com/docker/engine-api/types"
	//"github.com/docker/go-connections/nat"	
	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	//"github.com/docker/docker/api"
	//"github.com/gorilla/mux"
	//"github.com/diogomonica/actuary/actuary"


)

//2. Docker daemon configuration

//all seem to use GetProcCmdline -- systems call?

func TestRestrictNetTraffic(t *testing.T) {
	//calls .NetworkList(context.TODO(), netargs), fake a response network
	
	var network = []types.NetworkResource{{
			Name: "bridge",
			Options: map[string]string{"com.docker.network.bridge.enable_icc": "false"},
	}}



	for i := 0; i< 2; i++{
		nJSON, err := json.Marshal(network)

		if err != nil {
			t.Errorf("Could not convert network to json.")
		}

		p := callPairing{"/networks", nJSON}

		ts := testServer(t, p)
		
		res := RestrictNetTraffic(testTarget)

		defer ts.Close()

		if i == 0 && res.Status != "PASS" {
			t.Errorf("Net traffic restricted, should pass" )
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf("Net traffic not restricted, should not pass" )
		}

		//test fail case
		network[0].Options["com.docker.network.bridge.enable_icc"] = "true"
	}

 }

func TestCheckLoggingLevel(t *testing.T) {

	res := CheckLoggingLevel(testTarget)

	if res.Status != "PASS" {
			t.Errorf("check logging level error")
	}

}

func TestCheckIpTables(t *testing.T) {
	
}

func TestCheckInsecureRegistry(t *testing.T) {
	
}

func TestCheckAufsDriver(t *testing.T) {
	testTarget.Info.Driver = ""

	for i := 0; i< 2; i++{

		res := CheckAufsDriver(testTarget)

		if i == 0 && res.Status != "PASS" {
			t.Errorf("Not using the aufs storage driver, should pass." )
		}
		if i == 1 && res.Status == "PASS"{
			t.Errorf("Using the aufs storage driver, should not pass." )
		}

		//test fail case
		testTarget.Info.Driver = "aufs"
	}
}

func TestCheckTLSAuth(t *testing.T) {
	
}

func TestCheckUlimit(t *testing.T) {
	
}

func TestCheckUserNamespace(t *testing.T) {
	
}

func TestCheckDefaultCgroup(t *testing.T) {
	
}

func TestCheckBaseDevice(t *testing.T) {
	
}

func TestCheckAuthPlugin(t *testing.T) {
	
}

func TestCheckCentralLogging(t *testing.T) {
	
}

func TestCheckLegacyRegistry(t *testing.T) {
	
}
