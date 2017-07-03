package actuary


import (

	"encoding/json"
	"testing"
	"github.com/docker/engine-api/types"
)

//2. Docker daemon configuration

//This function is used in all functions that call getProcCmdLine -- replacing the output of getProcCmdLine for the pass case and fail case
func procCmdLineHelper(t *testing.T, orig func(t Target) Result, procPass []string, procFail []string, err1 string, err2 string){

	procFunction = func(procname string) (cmd []string, err error){
			err = nil
			cmd = procPass
			return
		}

	for i := 0; i< 2; i++{

		res := orig(testTarget)

		if i == 0 && res.Status != "PASS" {
				t.Errorf(err1)
		}

		//test fail case

		procFunction = func(procname string) (cmd []string, err error){
			err = nil
			cmd = procFail
			return
		}

		if i == 1 && res.Status == "PASS" {
				t.Errorf(err2)
		}
	}

	//restore
	procFunction = getProcCmdline
}


func TestRestrictNetTraffic(t *testing.T) {
	//calls .NetworkList(context.TODO(), netargs), fake a response network
	//Uses helper function "testServer," defined in dockerhost_test.go

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

//Following functions all use getProcCmdline -- replace this call with procCmdLineHelper
func TestCheckLoggingLevel(t *testing.T) {

	error1 := "Logging level set, should have passed."
	error2 := "Logging level not set, should not have passed."

	procCmdLineHelper(t, CheckLoggingLevel, []string{"--log-level=info"}, []string{"--log-level=notInfo"}, error1, error2)

}

func TestCheckIpTables(t *testing.T) {

	error1 := "Docker allowed to make changes to iptables, should have passed."
	error2 := "Docker not allowed to make changes to iptables, should not have passed."

	//This seems backwards? Shouldn't it be true, then false?

	procCmdLineHelper(t, CheckIpTables, []string{"--iptables=false"}, []string{"--iptables=true"}, error1, error2)

}

func TestCheckInsecureRegistry(t *testing.T) {

	error1 := "No insecure registries, should have passed."
	error2 := "Insecure registry, should not have passed."

	procCmdLineHelper(t, CheckInsecureRegistry,  []string{"--secure-registry"},  []string{"--insecure-registry"}, error1, error2)
	
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

	TLSOperationsPass := []string{"--tlsverify", "--tlscacert", "--tlscert", "--tlskey"}
	TLSOperationsFail:= []string{"--tlscacert", "--tlscert", "--tlskey"}

	error1 := "TLS configuration correct, should have passed."
	error2 := "TLS configuration is missing options, should not have passed."

	procCmdLineHelper(t, CheckTLSAuth, TLSOperationsPass, TLSOperationsFail, error1, error2)
	
}

func TestCheckUlimit(t *testing.T) {

	error1 := "Default ulimit set, should have passed."
	error2 := "Default ulimit not set, should not have passed."

	procCmdLineHelper(t, CheckUlimit, []string{"--default-ulimit"}, []string{""}, error1, error2)

}

func TestCheckUserNamespace(t *testing.T) {
	
	error1 := "User namespace support is enabled, should have passed."
	error2 := "User namespace support is not enabled, should not have passed."

	procCmdLineHelper(t, CheckUserNamespace, []string{"--userns-remap"}, []string{""}, error1, error2)

}

func TestCheckDefaultCgroup(t *testing.T) {

	error1 := "Default cgroup is used, should have passed."
	error2 := "Default cgroup is not used, should not have passed."
	
	procCmdLineHelper(t, CheckDefaultCgroup, []string{"--cgroup-parent"}, []string{""}, error1, error2)

}

func TestCheckBaseDevice(t *testing.T) {

	error1 := "Default device size has not been changed, should have passed."
	error2 := "Default device size has been changed, should not have passed."
	
	procCmdLineHelper(t, CheckBaseDevice, []string{"--storage-opt dm.basesize"}, []string{""}, error1, error2)

}

func TestCheckAuthPlugin(t *testing.T) {

	error1 := "Authorization plugin used, should have passed."
	error2 := "Authorization plugin not used, should not have passed."

	procCmdLineHelper(t, CheckAuthPlugin, []string{"--authorization-plugin"}, []string{""}, error1, error2)
}

func TestCheckCentralLogging(t *testing.T) {
	
	error1 := "Centralized and remote logging configured, should have passed."
	error2 := "Centralized and remote logging not configured, should not have passed."

	procCmdLineHelper(t, CheckCentralLogging, []string{"--log-driver"}, []string{""}, error1, error2)

}

func TestCheckLegacyRegistry(t *testing.T) {
	error1 := "Operations on legacy registry disabled, should have passed."
	error2 := "Operations on legacy registry not disabled, should not have passed."

	procCmdLineHelper(t, CheckLegacyRegistry, []string{"--disable-legacy-registry"}, []string{""}, error1, error2)

}
