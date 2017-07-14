package check

import (
	"bytes"
	"encoding/json"
	"flag"
	"github.com/diogomonica/actuary/actuary"
	"github.com/diogomonica/actuary/oututils"
	"github.com/diogomonica/actuary/profileutils"
	"github.com/spf13/cobra"
	"log"
	"net/http"
	"os"
	"strings"
)

var profile string
var output string
var tlsPath string
var server string
var dockerServer string
var tomlProfile profileutils.Profile
var results []actuary.Result
var actions map[string]actuary.Check

func init() {
	CheckCmd.Flags().StringVarP(&profile, "profile", "f", "", "file profile")
	CheckCmd.Flags().StringVarP(&output, "output", "o", "", "output filename")
	CheckCmd.Flags().StringVarP(&tlsPath, "tlsPath", "t", "", "Path to load certificates from")
	CheckCmd.Flags().StringVarP(&server, "server", "s", "", "Server for aggregating results")
	CheckCmd.Flags().StringVarP(&dockerServer, "dockerServer", "d", "", "Docker server to connect to tcp://<docker host>:<port>")
}

// docker service create --name actuary_check --global actuary_image actuary check --server <some hostname>
var (
	CheckCmd = &cobra.Command{
		Use:   "check <server name>",
		Short: "Run actuary checklist on a node",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := server
			var cmdArgs []string
			var hash string
			//flag.Parse()
			if tlsPath != "" {
				os.Setenv("DOCKER_CERT_PATH", tlsPath)
			}
			if dockerServer != "" {
				os.Setenv("DOCKER_HOST", dockerServer)
			} else {
				os.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
			}
			trgt, err := actuary.NewTarget()
			if err != nil {
				log.Fatalf("Unable to connect to Docker daemon: %s", err)
			}

			cmdArgs = flag.Args()

			if len(cmdArgs) == 2 { //./actuary2 check -f=mac-default.toml
				hash = cmdArgs[1]
				tomlProfile, err = profileutils.GetFromURL(hash)
				if err != nil {
					log.Fatalf("Unable to fetch profile. Exiting...")
				}
			} else if len(cmdArgs) == 0 || len(cmdArgs) == 1 {
				_, err := os.Stat(profile)
				if os.IsNotExist(err) {
					log.Fatalf("Invalid profile path: %s", profile)
				}
				tomlProfile = profileutils.GetFromFile(profile)
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
			rep := oututils.CreateReport(output)
			rep.Results = results
			switch strings.ToLower(output) {
			case "json":
				rep.WriteJSON()
			case "xml":
				rep.WriteXML()
			default:
				for _, res := range rep.Results {
					oututils.ConsolePrint(res)
				}
			}

			jsonResults, err := json.MarshalIndent(rep.Results, "", "  ")
			if err != nil {
				log.Fatalf("Unable to marshal results into JSON file")
			}

			var jsonStr = []byte(jsonResults)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
			if err != nil {
				log.Printf("ERROR: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("ERROR1: %v", err)
			}
			defer resp.Body.Close()

			return nil
		},
	}
)
