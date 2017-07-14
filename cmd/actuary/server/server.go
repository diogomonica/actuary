package server

import (
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

var (
	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "Aggregate actuary output for swarm",
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeCount := 1
			//Listen for incoming connections
			mux := http.NewServeMux()
			mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
				fileName := "/tmp/output" + strconv.Itoa(nodeCount)
				nodeCount = nodeCount + 1
				_, err := os.Create(fileName)
				if err != nil {
					log.Fatalf("Error creating file: %s", err)
				}
				f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0600)
				defer f.Close()
				if err != nil {
					log.Fatalf("Error opening file: %s", err)
				}
				output, err := ioutil.ReadAll(r.Body)
				if err != nil {
					log.Fatalf("Error reading: %s", err)
				}
				_, err = f.Write(output)
				if err != nil {
					log.Fatalf("Error writing file: %s", err)
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
