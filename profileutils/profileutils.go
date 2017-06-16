package profileutils

import (
	"crypto/sha1"
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
	url = serverAddr + hash
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error contacting the web server. Please verify your hash: %s", err)
	}
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
