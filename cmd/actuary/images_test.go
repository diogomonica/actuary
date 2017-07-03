package actuary


import (

	"testing"
)

//4. Container Images and Build File

func TestCheckContainerUser(t *testing.T) {
	t.Log("Setting all container users")

	containers := testTarget.Containers

	for _, container := range containers {
		container.Info.Config.User = "x"
	}

	for i := 0; i< 2; i++{

		res := CheckContainerUser(testTarget)

		if  i == 0 && res.Status != "PASS" {
			t.Errorf("All users checked, should have passed." )
		}

		if  i == 1 && res.Status == "PASS" {
			t.Errorf("All blank users, should not have passed." )
		}

		//fail case
		containers[0].Info.Config.User = ""
	}
}

func TestCheckContentTrust(t *testing.T) {
	//Question about os.GetEnv -- doesn't seem to work?
	//This might be too abstracted... not testing the function well enough

	trust = "1"

	for i := 0; i< 2; i++{

		res := CheckContentTrust(testTarget)

		if  i == 0 && res.Status != "PASS" {
			t.Errorf("Content trust for Docker enabled, should have passed." )
		}

		if  i == 1 && res.Status == "PASS" {
			t.Errorf("Content trust for Docker disabled, should not have passed." )
		}

		//fail case
		trust = ""
	}

}