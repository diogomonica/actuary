package profileutils

import (
	"crypto/sha1"
<<<<<<< HEAD
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/diogomonica/actuary/audit"
	"github.com/diogomonica/actuary"
	"github.com/fatih/color"
	"io/ioutil"
	"net/http"
	"log"
	"os"
	"path"
)

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

func JSONPrint(res []audit.Result, outfile string) {
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

// read audit profile using the API
func GetProfile(hash string) string {
	var profilePath string
	var serverAddr string 
	var url string

	serverAddr = "http://127.0.0.1:8000/"
=======
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
)

const serverAddr = "http://127.0.0.1:8000/"

type Profile struct {
	Audit []struct {
		Name      string
		Checklist []string
	}
}

//GetFromURL reads audit profile using the API
func GetFromURL(hash string) (p Profile, err error) {
	var url string
>>>>>>> master
	url = serverAddr + hash
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error contacting the web server. Please verify your hash: %s", err)
	}
<<<<<<< HEAD

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

func ReadProfile(profile string) actuary.Profile {
	var tomlProfile actuary.Profile
	_, err := toml.DecodeFile(profile, &tomlProfile)
	if err != nil {
		log.Fatalf("Error parsing TOML profile: %s", err)
	}
	return tomlProfile
}
=======
	body, _ := ioutil.ReadAll(resp.Body)
	bodyHash := fmt.Sprintf("%x", sha1.Sum(body))
	if bodyHash == hash {
		_, err = toml.DecodeReader(resp.Body, &p)
		if err != nil {
			log.Fatalf("Unable to decode profile: %s", err)
		}
	}
	return p, err
}

//GetFromFile reads an audit profile from a filesystem path
func GetFromFile(path string) (p Profile) {
	_, err := toml.DecodeFile(path, &p)
	if err != nil {
		log.Fatalf("Error parsing TOML profile: %s", err)
	}
	return p
}
>>>>>>> master
