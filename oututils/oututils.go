package oututils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"github.com/diogomonica/actuary/audit"
	"github.com/fatih/color"
)

type Report struct {
	filename string
	results  []audit.Result
}

//Create creates a new Report object
func CreateReport(path string) (r Report) {
	r.filename = path
	return r
}

func (r *Report) AddResult(res audit.Result) {
	r.results = append (r.results, res)
	return
}
//WriteXML prints the report into a XML file
// func (r *Report) WriteXML() (err error) {
//
// }

//WriteJSON prints the report into a JSON file
func (r *Report) WriteJSON() (err error) {
	res, err := json.Marshal(r.results)
	if err != nil {
		log.Fatalf("Unable to marshal results into JSON file")
	}
	err = ioutil.WriteFile(r.filename, res, 0644)
	if err != nil {
		log.Fatalf("Unable to write results to file")
	}
	return
}

//ConsolePrint outputs the result of each audit
func ConsolePrint(res audit.Result) {
	var status string
	bold := color.New(color.Bold).SprintFunc()
	if res.Status == "PASS" {
		status = color.GreenString("[PASS]")
	} else if res.Status == "WARN" {
		status = color.RedString("[WARN]")
	} else {
		status = color.CyanString("[INFO]")
	}

	fmt.Printf("%s - %s \n", status, bold(res.Name))

	if res.Output != "" {
		fmt.Printf("\t %s\n\n", res.Output)
	}
}
