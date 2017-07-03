package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/diogomonica/actuary/actuary"
	"github.com/diogomonica/actuary/oututils"
	"github.com/diogomonica/actuary/profileutils"
)

var profile = flag.String("profile", "", "Actuary profile file path")
var output = flag.String("output", "", "output filename")
//var outputType = flag.String("type", "json", "output type - XML or JSON")
var tlsPath = flag.String("tlspath", "", "Path to load certificates from")
var server = flag.String("server", "", "Docker server to connect to tcp://<docker host>:<port>")
var tomlProfile profileutils.Profile
var results []actuary.Result
var actions map[string]actuary.Check

func init() {
	flag.StringVar(profile, "f", "", "Actuary profile file path")
	flag.StringVar(output, "o", "", "output filename")
	//flag.StringVar(outputType, "oT", "", "output type - XML or JSON")
	flag.StringVar(tlsPath, "tls", "", "Path to load certificates from")
	flag.StringVar(server, "s", "", "Docker server to connect to tcp://<docker host>:<port>")
}

func main() {
	var cmdArgs []string
	var hash string

	flag.Parse()
	if *tlsPath != "" {
		os.Setenv("DOCKER_CERT_PATH", *tlsPath)
	}
	if *server != "" {
		os.Setenv("DOCKER_HOST", *server)
	} else {
		os.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	}
	trgt, err := actuary.NewTarget()
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

	actions := actuary.GetAuditDefinitions()

	//log.Printf("XXXXXXXX %s", []actuary.Result)

	//loop through the audits
	for category := range tomlProfile.Audit {
		if *output==""{
			log.Printf("Running Audit: %s", tomlProfile.Audit[category].Name)
		}	
		checks := tomlProfile.Audit[category].Checklist
		//cross-reference checks
		for _, check := range checks {
			if _, ok := actions[check]; ok {
				res := actions[check](trgt)
				results = append(results, res)
				//log.Printf("OUTPUTTYPE: %s", *outputType)
				if *output==""{
					oututils.ConsolePrint(res)
				}
			} else {
				log.Panicf("No check named %s", check)
			}
		}
	}

	if *output != "" {
		rep := oututils.CreateReport(*output)
		rep.Results = results
		switch strings.ToLower(*output) {
		case "json":
			rep.WriteJSON()
		case "xml":
			rep.WriteXML()
		}
	}
}
