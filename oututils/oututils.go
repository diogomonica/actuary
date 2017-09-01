package oututils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/diogomonica/actuary/actuary"
	"github.com/fatih/color"
	"io/ioutil"
	"log"
	"os"
	"path"
)

type Report struct {
	Filename string
	Results  []actuary.Result
}

// CreateReport creates a new Report object
func CreateReport(filename string) *Report {
	r := &Report{}
	if path.IsAbs(filename) {
		r.Filename = filename
	} else {
		curDir, err := os.Getwd()
		if err != nil {
			log.Fatalf("Unable to create report: %s", err)
		}
		r.Filename = path.Join(curDir, filename)
	}
	return r
}

// WriteJSON prints the report into a JSON file
func (r *Report) WriteJSON() (err error) {
	res, err := json.MarshalIndent(r.Results, "", "  ")
	if err != nil {
		log.Fatalf("Unable to marshal results into JSON file")
	}
	err = ioutil.WriteFile(r.Filename, res, 0644)
	log.Printf("writing json for %v", r.Filename)
	if err != nil {
		log.Fatalf("Unable to write results to file %s", err)
	}
	log.Printf("wrote")
	return
}

// WriteXML prints the report into an XML file
func (r *Report) WriteXML() (err error) {
	res, err := xml.MarshalIndent(r.Results, "", " ")
	if err != nil {
		log.Fatal("Unable to marshal results into XML file")
	}
	err = ioutil.WriteFile(r.Filename, res, 0644)
	if err != nil {
		log.Fatalf("Unable to write results to file %s", err)
	}
	return
}

// ConsolePrint outputs the result of each audit
func ConsolePrint(res actuary.Result) {
	var status string
	bold := color.New(color.Bold).SprintFunc()
	if res.Status == "PASS" {
		status = color.GreenString("[PASS]")
	} else if res.Status == "WARN" {
		status = color.RedString("[WARN]")
	} else if res.Status == "SKIP" {
		status = color.YellowString("[SKIP]")
	} else {
		status = color.CyanString("[INFO]")
	}

	fmt.Printf("%s - %s \n", status, bold(res.Name))

	if res.Output != "" {
		fmt.Printf("\t %s\n\n", res.Output)
	}
}
