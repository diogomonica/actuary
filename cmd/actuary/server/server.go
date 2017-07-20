package server

import (
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type outputData struct {
	Mu      *sync.Mutex
	Outputs map[string][]byte
}

var (
	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "Aggregate actuary output for swarm",
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeCount := 1
			mux := http.NewServeMux()
			m := make(map[string][]byte)
			var report = outputData{Mu: &sync.Mutex{}, Outputs: m}
			mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					output, err := ioutil.ReadAll(r.Body)
					if err != nil {
						log.Fatalf("Error reading: %s", err)
					}
					//_, err = f.Write(output)
					if err != nil {
						log.Fatalf("Error writing file: %s", err)
					}
					report.Mu.Lock()
					report.Outputs["output"+strconv.Itoa(nodeCount)] = output
					report.Mu.Unlock()
					nodeCount = nodeCount + 1
				}
			})

			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json")
					index := strings.Split(r.URL.Path, "/")
					report.Mu.Lock()
					w.Write(report.Outputs[index[len(index)-1]])
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
