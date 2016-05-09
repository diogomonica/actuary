package profileutils

import (
	"os"
	"testing"
)

type DummyProfile struct {
	path string
	file *os.File
}

func CreateProfile(fname string) (d DummyProfile, err error) {
	d.path = fname
	d.file, err = os.Create(fname)
	if err != nil {
		return d, err
	}
	return d, err
}

func (d *DummyProfile) Update(data string) {
	d.file.Write([]byte(data))
}

func (d *DummyProfile) Destroy() {
	d.file.Close()
	os.Remove(d.path)
}

func TestGetFromFile(t *testing.T) {
	t.Log("Creating dummy profile")
	dummy, _ := CreateProfile("/tmp/testprofile.toml")
	data := `[[Audit]]

Name = "Host Configuration"
Checklist = [
        "separate_partition"
        ]`
	dummy.Update(data)
	t.Log("Loading profile from dummy file")
	profile := GetFromFile(dummy.path)
	if profile.Audit[0].Name != "Host Configuration" {
		t.Errorf("Expected Host Configuration as Audit name, got %s instead", profile.Audit[0].Name)
	}
	if profile.Audit[0].Checklist[0] != "separate_partition" {
		t.Errorf("Expected seperate_partition as Check name, got %s instead", profile.Audit[0].Checklist[0])
	}
	dummy.Destroy()
}

// func TestGetFromURL(t *testing.T) {
//
// }
