package main

import (
	"flag"
	"fmt"
	"github.com/diogomonica/actuary/tests/dockerhost"
	"github.com/naoina/toml"
	"github.com/docker/engine-api/client"
    //"github.com/docker/engine-api/types"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var profile string
var hash string


//Audits are the benchmark categories (e.g Host Configuration, Docker conf etc.).
//A profile consists of a list of audits
type Profile struct {
    Audit []struct {
        Name string
        Checklist []string
        }
    }

// read audit profile from local file
func parseProfile(profile string) Profile {

	var tomlProfile Profile
	content, err := ioutil.ReadFile(profile)

	if err != nil {
		log.Fatalf("Error reading TOML profile from file:", err)
	}
	//unmarshal file content to struct
	err = toml.Unmarshal(content, &tomlProfile)
	if err != nil {
		log.Fatalf("Error parsing TOML profile:", err)
	}
	return tomlProfile
}

// read audit profile using the API
func getProfile(hash string) {

	url := "http://httpbin.org/get?a=" + hash
	resp, err := http.Get(url)

	if err != nil {
		fmt.Print("Error contacting the server:", err)
	}
	output, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(output)
	return
}

func main() {
	// parse command-line flags
	flag.StringVar(&profile, "profile", "default.json", "Audit profile path")
	flag.StringVar(&hash, "hash", "", "Hash for API")
	flag.Parse()

	if profile != "default.json" {
		_, err := os.Stat(profile)
		if os.IsNotExist(err) {
			log.Fatalf("Invalid profile path: %s", profile)
		}
	//initialize docker client	
    defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}
    cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.20", nil, defaultHeaders)
    if err != nil {
        log.Fatalf("Unable to connect to Docker daemon:", err)
    }
		tomlProfile := parseProfile(profile)
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
						log.Printf("Check: %s\nStatus: %s\nLog: %s\n", res.Name, res.Status, res.Output)
					} else {
						log.Panicf("No check named", check)
					}
				}
			} else {
				log.Panicf("No audit category named:", tomlProfile.Audit[category].Name)
			}
		}

	} else if hash != "" {
		getProfile(hash)

	} else {
		log.Fatalf("Something went wrong")
	}
}
