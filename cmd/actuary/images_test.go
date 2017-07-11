package actuary

import (
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"testing"
)

// 4. Container Images and Build File
func TestCheckContainerUserSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	testTarget.Containers = ContainerList{testTarget.Containers[0]}
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	infoConfig := &container.Config{User: "x"}
	testTarget.Containers[0].Info.Config = infoConfig
	res := CheckContainerUser(*testTarget)
	assert.Equal(t, "PASS", res.Status, "All users checked, should have passed.")
}

func TestCheckContainerUserFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	testTarget.Containers = ContainerList{testTarget.Containers[0]}
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	infoConfig := &container.Config{User: ""}
	testTarget.Containers[0].Info.Config = infoConfig
	res := CheckContainerUser(*testTarget)
	assert.Equal(t, "WARN", res.Status, "All blank users, should not have passed.")
}

func TestCheckContentTrustSuccess(t *testing.T) {
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
