package check

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/diogomonica/actuary/actuary"
	"github.com/diogomonica/actuary/oututils"
	"github.com/diogomonica/actuary/profileutils"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var profile string
var outputFormat string
var outputPath string
var tlsPath string
var server string
var dockerServer string
var swarm string
var tomlProfile profileutils.Profile
var results []actuary.Result
var actions map[string]actuary.Check

type Request struct {
	NodeID  []byte
	Results []byte
}

func init() {
	CheckCmd.Flags().StringVarP(&profile, "profile", "f", "", "file profile")
	CheckCmd.Flags().StringVarP(&swarm, "swarm", "w", "", "Spin up a container if running on a swarm")
	CheckCmd.Flags().StringVarP(&outputFormat, "format", "o", "", "output format type (json/xml)")
	CheckCmd.Flags().StringVarP(&outputPath, "path", "p", "", "Absolute path for json output")
	CheckCmd.Flags().StringVarP(&tlsPath, "tlsPath", "t", "", "Path to load certificates from")
	CheckCmd.Flags().StringVarP(&server, "server", "s", "", "Server for aggregating results")
	CheckCmd.Flags().StringVarP(&dockerServer, "dockerServer", "d", "", "Docker server to connect to tcp://<docker host>:<port>")
}

func HttpClient() (client *http.Client) {
	uckey := os.Getenv("X509_USER_KEY")
	ucert := os.Getenv("X509_USER_CERT")
	x509cert, err := tls.LoadX509KeyPair(ucert, uckey)
	if err != nil {
		panic(err.Error())
	}
	certs := []tls.Certificate{x509cert}
	if len(certs) == 0 {
		client = &http.Client{}
		return
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: certs,
			InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr}
	return
}

// Log in and retrieve token
func basicAuth(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://server:8000/token", nil)
	if err != nil {
		log.Fatalf("Error generating request: %v", err)
	}
	var pw []byte
	pw, err = ioutil.ReadFile(os.Getenv("TOKEN_PASSWORD"))
	if err != nil {
		log.Fatalf("Could not read password: %v", err)
	}
	req.SetBasicAuth("defaultUser", string(pw))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Basic auth: %v", err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("Status code: %v", resp.StatusCode)
	}
	defer resp.Body.Close()
	bodyText, err := ioutil.ReadAll(resp.Body)
	s := string(bodyText)
	return s
}

func sendResults(out io.ReadCloser, rep *oututils.Report) {
	urlPOST := server
	tr := tar.NewReader(out)
	_, err := tr.Next()
	if err != nil {
		log.Fatalf("Error with tar %v", err)
	}
	decoder := json.NewDecoder(tr)
	var testResults []actuary.Result = nil
	// Read open bracket
	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Error with open bracket: %v", err)
	}
	// While the array contains values
	for decoder.More() {
		var result actuary.Result
		// decode an array value (test result)
		err := decoder.Decode(&result)
		if err != nil {
			log.Fatalf("Error reading values: %v", err)
		}
		testResults = append(testResults, result)
	}
	// Read closing bracket
	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Error with close bracket: %v", err)
	}
	rep.Results = testResults
	switch strings.ToLower(outputFormat) {
	case "json":
		rep.WriteJSON()
	case "xml":
		rep.WriteXML()
	default:
		if server != "" {
			jsonResults, err := json.MarshalIndent(rep.Results, "", "  ")
			if err != nil {
				log.Fatalf("Unable to marshal results into JSON file: %s", err)
			}
			var reqStruct = Request{NodeID: []byte(os.Getenv("NODE")), Results: jsonResults}
			result, err := json.Marshal(reqStruct)
			if err != nil {
				log.Fatalf("Could not marshal request: %v", err)
			}
			reqPost, err := http.NewRequest("POST", urlPOST, bytes.NewBuffer(result))
			if err != nil {
				log.Fatalf("Could not create a new request: %v", err)
			}
			reqPost.Header.Set("Content-Type", "application/json")
			client := HttpClient()

			token := basicAuth(client)
			var bearer = "Bearer " + token
			reqPost.Header.Add("authorization", bearer)
			respPost, err := client.Do(reqPost)
			if err != nil {
				log.Fatalf("Could not send post request to client: %v", err)
			}
			defer respPost.Body.Close()
		} else {
			log.Fatalf("No server specified for results.")
		}
	}
}

var (
	CheckCmd = &cobra.Command{
		Use:   "check <server name>",
		Short: "Run actuary checklist on a node",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set up container for each node to collect results
			if strings.ToLower(swarm) == "true" {
				ctx := context.Background()
				cli, err := client.NewEnvClient()
				if err != nil {
					log.Fatalf("Could not create new client: %s", err)
				}
				_, err = cli.ImagePull(ctx, "oliviabarnett/actuary:actuary_image", types.ImagePullOptions{})
				if err != nil {
					log.Fatalf("Could not pull image: %s", err)
				}
				resp, err := cli.ContainerCreate(ctx, &container.Config{
					Image: "oliviabarnett/actuary:actuary_image",
					Cmd:   []string{"check", "-f=cmd/actuary/mac-default.toml", "-o=json", "-p=" + strings.ToLower(outputPath) + "/json", "-s=https://server:8000/results", "--swarm=false"}},
					&container.HostConfig{
						Binds:  []string{"/var/run/docker.sock:/var/run/docker.sock", "/lib/systemd:/lib/systemd", "/usr/lib/systemd:/usr/lib/systemd", "/var/lib:/var/lib", "/etc:/etc"},
						CapAdd: strslice.StrSlice{"audit_control"},
						LogConfig: container.LogConfig{
							Type: "json-file",
						},
						PidMode:    container.PidMode("host"),
						Privileged: true,
					},
					nil, "")
				if err != nil {
					log.Fatalf("Could not create new container: %s", err)
				}
				if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
					log.Fatalf("Could not start new container: %s", err)
				}
				resultC, errC := cli.ContainerWait(ctx, resp.ID, "")

				select {
				case err := <-errC:
					log.Fatalf("Container wait: %s", err)
				case _ = <-resultC:
					path, err := os.Getwd()
					if err != nil {
						log.Fatalf("Could not get path %v", err)
					}
					rep := oututils.CreateReport(path + "/output/" + os.Getenv("NODE") + "." + outputFormat)
					// Copy out actuary results from container
					out, _, err := cli.CopyFromContainer(ctx, resp.ID, outputPath+"/json")
					if err != nil {
						log.Fatalf("Could not retrieve container logs: %s", err)
					}
					// Send results to server or output as file
					sendResults(out, rep)
					// Container no longer needed after results copied out
					cli.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{})
				}
				// Within container, run actuary
			} else {
				var cmdArgs []string
				var hash string
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
				if len(cmdArgs) == 2 {
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
				rep := &oututils.Report{Filename: outputPath, Results: results}
				err = rep.WriteJSON()
				if err != nil {
					log.Fatalf("Error writing json file %v", err)
				}
			}
			return nil
		},
	}
)
