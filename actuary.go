package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/diogomonica/actuary/tests/dockerhost"
	"github.com/docker/engine-api/client"
	"github.com/fatih/color"
	"io/ioutil"
	"log"
	"os"
)

//Profile is an array of Audits
type Profile struct {
	Audit []struct {
		Name      string
		Checklist []string
	}
}

var profile = flag.String("profile", "", "Audit profile path")
var hash = flag.String("hash", "", "Hash for API")
var output = flag.String("output", "", "JSON output filename")
var tomlProfile Profile
var results []dockerhost.Result
var clientHeaders map[string]string

func parseProfile(profile string) Profile {
	_, err := toml.DecodeFile(profile, &tomlProfile)
	if err != nil {
		log.Fatalf("Error parsing TOML profile:", err)
	}
	return tomlProfile
}

// read audit profile using the API
func getProfile(hash string) string {

	return "This func has not been implemented yet"
}

func consoleOutput(res dockerhost.Result) {
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

func jsonOutput(res []dockerhost.Result, outfile string) {
	results, err := json.Marshal(res)
	if err != nil {
		log.Fatalf("Unable to marshal results into JSON file")
	}
	err = ioutil.WriteFile(outfile, results, 0644)
	if err != nil {
		log.Fatalf("Unable to write results to file")
	}
	return
}

func init() {
	flag.StringVar(profile, "p", "", "Audit profile path")
	flag.StringVar(hash, "h", "", "Hash for API")
	flag.StringVar(output, "o", "", "JSON output filename")

	clientHeaders = make(map[string]string)
	clientHeaders["User-Agent"] = "engine-api-cli-1.0"
}

func main() {

	flag.Parse()
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, clientHeaders)
	if err != nil {
		log.Fatalf("Unable to connect to Docker daemon:", err)
	}

	if *hash != "" {
		remoteProfile := getProfile(*hash)
		tomlProfile = parseProfile(remoteProfile)
	} else {
		_, err := os.Stat(*profile)
		if os.IsNotExist(err) {
			log.Fatalf("Invalid profile path: %s", *profile)
		}
		tomlProfile = parseProfile(*profile)
	}

	//loop through the audits
	for category := range tomlProfile.Audit {
		if tomlProfile.Audit[category].Name == "Host Configuration" {
			log.Printf("Running Host Configuration checks")
			checks := tomlProfile.Audit[category].Checklist
			actions := dockerhost.GetAuditDefinitions()
			//cross-reference checks
			for _, check := range checks {
				if _, ok := actions[check]; ok {
					res := actions[check](cli)
					results = append(results, res)
					consoleOutput(res)
				} else {
					log.Panicf("No check named", check)
				}
			}
		} else {
			log.Panicf("No audit category named:", tomlProfile.Audit[category].Name)
		}
	}

	if *output != "" {
		jsonOutput(results, *output)
	}
}
