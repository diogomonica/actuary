package actuary

import (
	"os"
	"testing"
)

//tests getCmdOption helper function
func TestGetCmdOption(t *testing.T) {
	t.Log("Creating dummy cmd line")
	cmdLine := []string{"dummy", "--opt=1", "--opt2=2"}
	exists, val := getCmdOption(cmdLine, "opt")
	if exists == false {
		t.Errorf("opt1 should exist, got false instead\n")
	}
	if val != "1" {
		t.Errorf("Expected val equal to 1, got %s instead", val)
	}
}

func TestLookupFile(t *testing.T) {
	t.Log("Creating dummy file")

	os.Create("/tmp/dummy")
	knownDirs := []string{"/etc/", "/tmp"}
	info, err := lookupFile("dummy", knownDirs)
	if err != nil {
		t.Errorf("Unexpected error: %v\n", err)
	}
	if info.Name() != "dummy" {
		t.Errorf("Expected filename 'dummy', got %s instead", info.Name())
	}
}

func TestGetCmdOutput(t *testing.T) {
	t.Log("Executing 'echo hello'")
	out, err := getCmdOutput("echo", "hello")
	if err != nil {
		t.Errorf("Unexpected error: %v\n", err)
	}
	if string(out) != "hello\n" {
		t.Errorf("Expected output 'hello', got %s instead", string(out))
	}
}
