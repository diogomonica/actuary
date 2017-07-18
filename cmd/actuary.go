package main

import (
	"flag"
	"github.com/diogomonica/actuary/actuary"
	"github.com/diogomonica/actuary/oututils"
	"github.com/diogomonica/actuary/profileutils"
	"log"
	"os"
	"strings"
)

var profile = flag.String("profile", "", "Actuary profile file path")
var outputType = flag.String("output", "", "output type")
var outputFile = flag.String("file", "output", "output file")
var tlsPath = flag.String("tlspath", "", "Path to load certificates from")
var server = flag.String("server", "", "Docker server to connect to tcp://<docker host>:<port>")
var tomlProfile profileutils.Profile
var results []actuary.Result
var actions map[string]actuary.Check

func init() {
	flag.StringVar(profile, "f", "", "Actuary profile file path")
	flag.StringVar(outputType, "o", "", "output type")
	flag.StringVar(outputFile, "of", "", "output file")
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
	for category := range tomlProfile.Audit {
		checks := tomlProfile.Audit[category].Checklist
		for _, check := range checks {
			if _, ok := actions[check]; ok {
				res := actions[check](trgt)
				results = append(results, res)
			} else {
				log.Panicf("No check named %s", check)
			}
		}
	}
	rep := oututils.CreateReport(*outputFile)
	rep.Results = results
	switch strings.ToLower(*outputType) {
	case "json":
		rep.WriteJSON()
	case "xml":
		rep.WriteXML()
	default:
		for _, res := range rep.Results {
			oututils.ConsolePrint(res)
		}
	}
}
