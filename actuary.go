package main

import (
	//"bytes"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/diogomonica/actuary/audit"
	"github.com/diogomonica/actuary/audit/dockerhost"
	"github.com/diogomonica/actuary/audit/dockerconf"
	"github.com/diogomonica/actuary/audit/dockerfiles"
	"github.com/diogomonica/actuary/audit/container/images"
	"github.com/diogomonica/actuary/audit/container/runtime"
	"github.com/docker/engine-api/client"
	"github.com/fatih/color"
	"io/ioutil"
	//"io"
	"net/http"
	"log"
	"os"
	"path"
)

//Profile is an array of Audits
type Profile struct {
	Audit []struct {
		Name      string
		Checklist []string
	}
}

var profile = flag.String("profile", "", "Actuary profile file path")
var output = flag.String("output", "", "JSON output filename")
var tomlProfile Profile
var results []audit.Result
var clientHeaders map[string]string
var actions map[string]audit.Check

func parseProfile(profile string) Profile {
	_, err := toml.DecodeFile(profile, &tomlProfile)
	if err != nil {
		log.Fatalf("Error parsing TOML profile:", err)
	}
	return tomlProfile
}

// read audit profile using the API
func getProfile(hash string) string {
	var profilePath string
	var serverAddr string 
	var url string

	serverAddr = "http://127.0.0.1:8000/"
	url = serverAddr + hash
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error contacting the web server. Please verify your hash: %s", err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	bodyHash := fmt.Sprintf("%x", sha1.Sum(body))
	if bodyHash == hash {
		profilePath = path.Join("/tmp",hash)
		profile, err := os.Create(profilePath)
		if err != nil {
			log.Fatalf("Unable to create profile: %s", err)
		}
		_, err = profile.Write(body)
		if err != nil {
			log.Fatalf("Unable to copy data from HTTP response: %s", err)
		}

	} 
	return profilePath
}

func consoleOutput(res audit.Result) {
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

func jsonOutput(res []audit.Result, outfile string) {
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
	flag.StringVar(profile, "f", "", "Actuary profile file path")
	flag.StringVar(output, "o", "", "JSON output filename")

	clientHeaders = make(map[string]string)
	clientHeaders["User-Agent"] = "engine-api-cli-1.0"
}

func main() {
	var cmdArgs []string
	var hash string
	var auditName string
	
	flag.Parse()
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, clientHeaders)
	if err != nil {
		log.Fatalf("Unable to connect to Docker daemon:", err)
	}

	cmdArgs = flag.Args()
	if len(cmdArgs) == 1 {
		hash = cmdArgs[0]
		remoteProfile := getProfile(hash)
		if remoteProfile == "" {
			log.Fatalf("Unable to fetch profile. Exiting...")
		}
		tomlProfile = parseProfile(remoteProfile)
	} else if len(cmdArgs) == 0 {
		_, err := os.Stat(*profile)
		if os.IsNotExist(err) {
			log.Fatalf("Invalid profile path: %s", *profile)
		}
		tomlProfile = parseProfile(*profile)
	} else {
		log.Fatalf("Unsupported number of arguments. Use -h for help")
	}

	//loop through the audits
	for category := range tomlProfile.Audit {
		switch auditName = tomlProfile.Audit[category].Name; auditName {
		case "Host Configuration":
			actions = dockerhost.GetAuditDefinitions()		
		case "Docker daemon configuration":
			actions = dockerconf.GetAuditDefinitions()
		case "Docker daemon configuration files":
			actions = dockerfiles.GetAuditDefinitions()
		case "Container Images and Build File" :
			actions = images.GetAuditDefinitions()
		case "Container Runtime" :
			actions = runtime.GetAuditDefinitions()
		default: 
			log.Panicf("No audit category named:", auditName)
			continue
		}
		log.Printf("Running Audit: %s", auditName)
		checks := tomlProfile.Audit[category].Checklist
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
	}

	if *output != "" {
		jsonOutput(results, *output)
	}
}
