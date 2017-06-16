package actuary

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// 4. Container Images and Build File
func TestCheckContainerUserSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	containers := testTarget.Containers
	for _, container := range containers {
		container.Info.Config.User = "x"
	}
	res := CheckContainerUser(*testTarget)
	assert.Equal(t, "PASS", res.Status, "All users checked, should have passed.")
}

func TestCheckContainerUserFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	containers := testTarget.Containers
	containers[0].Info.Config.User = ""
	res := CheckContainerUser(*testTarget)
	assert.Equal(t, "WARN", res.Status, "All blank users, should not have passed.")
}

func TestCheckContentTrustSuccess(t *testing.T) {
	// Question about os.GetEnv -- doesn't seem to work?
	// This might be too abstracted... not testing the function well enough
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	trust = "1"
	res := CheckContentTrust(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Content trust for Docker enabled, should have passed.")
}

func TestCheckContentTrustFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	trust = ""
	res := CheckContentTrust(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Content trust for Docker disabled, should not have passed.")
}
