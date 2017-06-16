package actuary

import (
	"encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// 2. Docker daemon configuration
// Calls .NetworkList(context.TODO(), netargs), fake a response network
// Uses helper function "testServer," defined in dockerhost_test.go
func TestRestrictNetTrafficSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var network = []types.NetworkResource{{
		Name:    "bridge",
		Options: map[string]string{"com.docker.network.bridge.enable_icc": "false"},
	}}
	nJSON, err := json.Marshal(network)
	if err != nil {
		t.Errorf("Could not convert network to json.")
	}
	p := callPairing{"/networks", nJSON}
	ts := testTarget.testServer(t, p)
	res := RestrictNetTraffic(*testTarget)
	defer ts.Close()
	assert.Equal(t, "PASS", res.Status, "Net traffic restricted, should pass")
}

func TestRestrictNetTrafficFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	var network = []types.NetworkResource{{
		Name:    "bridge",
		Options: map[string]string{"com.docker.network.bridge.enable_icc": "true"},
	}}
	nJSON, err := json.Marshal(network)
	if err != nil {
		t.Errorf("Could not convert network to json.")
	}
	p := callPairing{"/networks", nJSON}
	ts := testTarget.testServer(t, p)
	res := RestrictNetTraffic(*testTarget)
	defer ts.Close()
	assert.Equal(t, "WARN", res.Status, "Net traffic not restricted, should not pass")
}

// Following functions all use getProcCmdline -- replace this call with procCmdLineHelper
func TestCheckLoggingLevelSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--log-level=info"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckLoggingLevel(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Logging level set, should have passed.")
}

func TestCheckLoggingLevelFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--log-level=notInfo"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckLoggingLevel(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Logging level not set, should not have passed.")
}

func TestCheckIpTablesSuccess(t *testing.T) {
	// This seems backwards? Shouldn't it be true, then false?
	testTarget, err := NewTestTarget([]string{"--iptables=false"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckIpTables(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Docker allowed to make changes to iptables, should have passed.")
}

func TestCheckIpTablesFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--iptables=true"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckIpTables(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Docker not allowed to make changes to iptables, should not have passed.")
}

func TestCheckInsecureRegistrySuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--secure-registry"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckInsecureRegistry(*testTarget)
	assert.Equal(t, "PASS", res.Status, "No insecure registries, should have passed")
}

func TestCheckInsecureRegistryFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--insecure-registry"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckInsecureRegistry(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Insecure registry, should not have passed.")
}

func TestCheckAufsDriverSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	testTarget.Info.Driver = ""
	res := CheckAufsDriver(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Not using the aufs storage driver, should pass.")
}

func TestCheckAufsDriverFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	testTarget.Info.Driver = "aufs"
	res := CheckAufsDriver(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Using the aufs storage driver, should not pass.")
}

func TestCheckTLSAuthSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--tlsverify", "--tlscacert", "--tlscert", "--tlskey"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckTLSAuth(*testTarget)
	assert.Equal(t, "PASS", res.Status, "TLS configuration correct, should have passed.")
}

func TestCheckTLSAuthFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--tlscacert", "--tlscert", "--tlskey"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckTLSAuth(*testTarget)
	assert.Equal(t, "WARN", res.Status, "TLS configuration is missing options, should not have passed.")
}

func TestCheckUlimitSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--default-ulimit"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckUlimit(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Default ulimit set, should have passed.")
}

func TestCheckUlimitFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckUlimit(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Default ulimit not set, should not have passed.")
}

func TestCheckUserNamespaceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--userns-remap"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckUserNamespace(*testTarget)
	assert.Equal(t, "PASS", res.Status, "User namespace support is enabled, should have passed.")
}

func TestCheckUserNamespaceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckUserNamespace(*testTarget)
	assert.Equal(t, "WARN", res.Status, "User namespace support is not enabled, should not have passed.")
}

func TestCheckDefaultCgroupSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--cgroup-parent"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckDefaultCgroup(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Default cgroup is used, should have passed.")
}

func TestCheckDefaultCgroupFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckDefaultCgroup(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Default cgroup is not used, should not have passed.")
}

func TestCheckBaseDeviceSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--storage-opt dm.basesize"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckBaseDevice(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Default device size has not been changed, should have passed.")
}

func TestCheckBaseDeviceFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckBaseDevice(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Default device size has been changed, should not have passed.")
}

func TestCheckAuthPluginSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--authorization-plugin"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckAuthPlugin(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Authorization plugin used, should have passed.")
}

func TestCheckAuthPluginFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckAuthPlugin(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Authorization plugin not used, should not have passed.")
}

func TestCheckCentralLoggingSuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--log-driver"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckCentralLogging(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Centralized and remote logging configured, should have passed.")
}

func TestCheckCentralLoggingFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckCentralLogging(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Centralized and remote logging not configured, should not have passed.")
}

func TestCheckLegacyRegistrySuccess(t *testing.T) {
	testTarget, err := NewTestTarget([]string{"--disable-legacy-registry"})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckLegacyRegistry(*testTarget)
	assert.Equal(t, "PASS", res.Status, "Operations on legacy registry disabled, should have passed.")
}

func TestCheckLegacyRegistryFail(t *testing.T) {
	testTarget, err := NewTestTarget([]string{""})
	if err != nil {
		t.Errorf("Could not create testTarget")
	}
	res := CheckLegacyRegistry(*testTarget)
	assert.Equal(t, "WARN", res.Status, "Operations on legacy registry not disabled, should not have passed.")
}
