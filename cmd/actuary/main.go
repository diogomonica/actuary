package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/diogomonica/actuary/checks"
	"github.com/diogomonica/actuary/oututils"
	"github.com/diogomonica/actuary/profileutils"
	"github.com/docker/engine-api/client"
)

var profile = flag.String("profile", "", "Actuary profile file path")
var output = flag.String("output", "", "output filename")
var outputType = flag.String("type", "json", "output type - XML or JSON")
var tomlProfile profileutils.Profile
var clientHeaders map[string]string
var results []checks.Result
var actions map[string]checks.Check

func init() {
	flag.StringVar(profile, "f", "", "Actuary profile file path")
	flag.StringVar(output, "o", "", "output filename")
	flag.StringVar(outputType, "", "json", "output type - XML or JSON")

	clientHeaders = make(map[string]string)
	clientHeaders["User-Agent"] = "engine-api-cli-1.0"
}

func main() {
	var cmdArgs []string
	var hash string

	flag.Parse()
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, clientHeaders)
	if err != nil {
		log.Fatalf("Unable to connect to Docker daemon: %s", err)
	}

	cmdArgs = flag.Args()
	if len(cmdArgs) == 1 {
		hash = cmdArgs[0]
		tomlProfile, err = profileutils.GetFromURL(hash)
		if err != nil {
			log.Fatalf("Unable to fetch profile. Exiting...")
		}
	} else if len(cmdArgs) == 0 {
		_, err := os.Stat(*profile)
		if os.IsNotExist(err) {
			log.Fatalf("Invalid profile path: %s", *profile)
		}
		tomlProfile = profileutils.GetFromFile(*profile)
	} else {
		log.Fatalf("Unsupported number of arguments. Use -h for help")
	}

	actions := checks.GetAuditDefinitions()
	//loop through the audits
	for category := range tomlProfile.Audit {
		log.Printf("Running Audit: %s", tomlProfile.Audit[category].Name)
		checks := tomlProfile.Audit[category].Checklist
		//cross-reference checks
		for _, check := range checks {
			if _, ok := actions[check]; ok {
				res := actions[check](cli)
				results = append(results, res)
				oututils.ConsolePrint(res)
			} else {
				log.Panicf("No check named %s", check)
			}
		}
	}

	if *output != "" {
		rep := oututils.CreateReport(*output)
		rep.Results = results
		switch strings.ToLower(*outputType) {
		case "json":
			rep.WriteJSON()
		case "xml":
			rep.WriteXML()
		}
	}
}
