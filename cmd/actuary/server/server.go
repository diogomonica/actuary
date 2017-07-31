package server

import (
	"encoding/json"
	"github.com/diogomonica/actuary/cmd/actuary/check"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var htmlPath string

func init() {
	ServerCmd.Flags().StringVarP(&htmlPath, "htmlPath", "p", filepath.Join(os.Getenv("GOPATH"), "/src/github.com/diogomonica/actuary/cmd/actuary/results"), "Path to folder that holds html, js, css for browser.")
}

type outputData struct {
	Mu      *sync.Mutex
	Outputs map[string][]byte
}

var (
	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "Aggregate actuary output for swarm",
		RunE: func(cmd *cobra.Command, args []string) error {
			mux := http.NewServeMux()
			m := make(map[string][]byte)
			var report = outputData{Mu: &sync.Mutex{}, Outputs: m}
			var reqList []check.Request

			mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					output, err := ioutil.ReadAll(r.Body)
					if err != nil {
						log.Fatalf("Error reading: %s", err)
					}
					// Get nodeID, results passed in from check on a particular node
					var req check.Request
					err = json.Unmarshal(output, &req)
					if err != nil {
						log.Fatalf("Error unmarshalling id: %s", err)
					}
					reqList = append(reqList, req)
					nodeID := string(req.NodeID)
					log.Printf("NODE ID %v", nodeID)
					results := req.Results
					report.Mu.Lock()
					report.Outputs[nodeID] = results
					report.Mu.Unlock()
				}
			})

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				index := strings.Split(r.URL.Path, "/")
				if index[len(index)-1] != "" {
					w.Header().Set("Content-Type", "application/json") //change to writeHeader!
					report.Mu.Lock()
					w.Write(report.Outputs[index[len(index)-1]])
					report.Mu.Unlock()
				} else {
					log.Fatalf("Node ID not entered")
				}
			})

			mux.HandleFunc("/results/", func(w http.ResponseWriter, r *http.Request) {
				path := htmlPath
				handler := http.StripPrefix("/results/", http.FileServer(http.Dir(path)))
				handler.ServeHTTP(w, r)
			})

			mux.HandleFunc("/getNodes", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				log.Printf("/getNodes HIT")
				for _, req := range reqList {
					w.Write(req.NodeID)
					w.Write([]byte(" "))
					log.Printf("WRITTEN NODE ID: %s", string(req.NodeID))
				}
			})

			mux.HandleFunc("/all", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json") //change to writeHeader!
					report.Mu.Lock()
					for output := range report.Outputs {
						w.Write([]byte(output))
					}
					report.Mu.Unlock()
				}
			})

			err := http.ListenAndServe(":8000", mux)
			if err != nil {
				log.Fatalf("Error with listen and serve: %s", err)
			}
			return nil
		},
	}
)
