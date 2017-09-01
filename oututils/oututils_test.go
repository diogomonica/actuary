package oututils

import (
	"encoding/json"
	"encoding/xml"
	"github.com/diogomonica/actuary/actuary"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"
)

func TestCreateReport(t *testing.T) {
	curDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Unable to create report: %s", err)
	}
	filename := path.Join(curDir, "testReport")
	testReport := CreateReport("testReport")
	assert.Equal(t, filename, testReport.Filename, "Failed to create a report")
}

func TestWriteJSON(t *testing.T) {
	testReport := CreateReport("testReport.json")
	result := actuary.Result{Name: "name", Status: "status", Output: "output"}
	testReport.Results = append(testReport.Results, result)
	err := testReport.WriteJSON()
	if err != nil {
		log.Fatalf("Could not write report in JSON: %v", err)
	}
	content, err := ioutil.ReadFile(testReport.Filename)
	os.Remove(testReport.Filename)
	if err != nil {
		log.Fatalf("Could not read out file %v", err)
	}
	var c []actuary.Result
	json.Unmarshal(content, &c)
	assert.Equal(t, c[0], result, "JSON not created correctly")
}

func TestWriteXML(t *testing.T) {
	testReport := CreateReport("testReport.xml")
	result := actuary.Result{Name: "name", Status: "status", Output: "output"}
	testReport.Results = append(testReport.Results, result)
	err := testReport.WriteXML()
	if err != nil {
		log.Fatalf("Could not write report in XML: %v", err)
	}
	content, err := ioutil.ReadFile(testReport.Filename)
	os.Remove(testReport.Filename)
	if err != nil {
		log.Fatalf("Could not read out file %v", err)
	}
	var c []actuary.Result
	xml.Unmarshal(content, &c)
	assert.Equal(t, c[0], result, "not right")
}
