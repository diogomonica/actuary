package server

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

type outputData struct {
	Mu      *sync.Mutex
	Outputs map[string][]byte
}

type Request struct {
	NodeID  []byte
	Results []byte
}

var (
	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "Aggregate actuary output for swarm",
		RunE: func(cmd *cobra.Command, args []string) error {
			mux := http.NewServeMux()
			m := make(map[string][]byte)
			var report = outputData{Mu: &sync.Mutex{}, Outputs: m}
			mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					output, err := ioutil.ReadAll(r.Body)
					if err != nil {
						log.Fatalf("Error reading: %s", err)
					}
					var req Request
					err = json.Unmarshal(output, &req)
					if err != nil {
						log.Fatalf("Error unmarshalling id: %s", err)
					}
					nodeID := string(req.NodeID)
					results := req.Results
					report.Mu.Lock()
					report.Outputs[nodeID] = results
					report.Mu.Unlock()
				}
			})

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json") //change to writeHeader!
					index := strings.Split(r.URL.Path, "/")
					report.Mu.Lock()
					w.Write(report.Outputs[index[len(index)-1]])
					report.Mu.Unlock()
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
