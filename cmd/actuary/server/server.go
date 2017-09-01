package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/diogomonica/actuary/cmd/actuary/check"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

var htmlPath string

func init() {
	ServerCmd.Flags().StringVarP(&htmlPath, "htmlPath", "p", "/cmd/actuary/server/results", "Path to folder that holds html, js, css for browser -- relative to current working directory.")
}

type outputData struct {
	Mu      *sync.Mutex
	Outputs map[string][]byte
}

type nodeRoles struct {
	Managers []swarm.Node
	Workers  []swarm.Node
}

func AddMiddleware(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for _, mw := range middleware {
		h = mw(h)
	}
	return h
}

func (report *outputData) getResults(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeID")
	if nodeID != "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.WriteHeader(http.StatusOK)
		report.Mu.Lock()
		w.Write(report.Outputs[nodeID])
		report.Mu.Unlock()
	} else {
		log.Fatalf("Node ID not entered")
	}
}

func (report *outputData) postResults(w http.ResponseWriter, r *http.Request, reqList *[]check.Request) {
	output, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Error reading: %s", err)
	}
	var req check.Request
	err = json.Unmarshal(output, &req)
	if err != nil {
		log.Fatalf("Error unmarshalling id: %s", err)
	}

	*reqList = append(*reqList, req)
	nodeID := string(req.NodeID)
	results := req.Results
	report.Mu.Lock()
	report.Outputs[nodeID] = results
	report.Mu.Unlock()
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
			// Get list of all nodes in the swarm via Docker API call
			// Used for comparison to see which nodes have yet to be processed
			ctx := context.Background()
			cli, err := client.NewEnvClient()
			if err != nil {
				log.Fatalf("Could not create new client: %s", err)
			}
			nodeList, err := cli.NodeList(ctx, types.NodeListOptions{})
			if err != nil {
				log.Fatalf("Could not get list of nodes: %s", err)
			}
			cfg := &tls.Config{
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
			srv := &http.Server{
				Addr:         ":8000",
				Handler:      mux,
				TLSConfig:    cfg,
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
			}
			api := NewAPI(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
			mux.Handle("/token", api.Tokens)
			// Send official list of nodes from docker client to browser
			mux.HandleFunc("/getNodeList", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
				w.WriteHeader(http.StatusOK)
				var nodes = nodeRoles{Managers: nil, Workers: nil}
				var b bytes.Buffer
				for _, node := range nodeList {
					if node.ManagerStatus == nil {
						nodes.Workers = append(nodes.Workers, node)
					} else {
						nodes.Managers = append(nodes.Managers, node)
					}
				}
				for _, manager := range nodes.Managers {
					b.Write([]byte(manager.ID + " "))
				}
				b.Write([]byte("--"))
				for _, worker := range nodes.Workers {
					b.Write([]byte(worker.ID + " "))
				}
				b.WriteTo(w)
			})
			// Submission of results: Where nodes send DATA from check.go
			// Authorization of submission of results
			postResults := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { report.postResults(w, r, &reqList) })
			mux.Handle("/results", AddMiddleware(postResults, api.Authenticate))

			// Request of results: where javascript requests receives specific node DATA
			// Authorization of requesting of results
			getResults := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { report.getResults(w, r) })
			mux.Handle("/result", AddMiddleware(getResults, api.Authenticate))

			// Path to return css/js/html
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				currentDir, err := os.Getwd()
				if err != nil {
					log.Fatalf("Error getting current directory: %s", err)
				}
				path := filepath.Join(currentDir, htmlPath)
				w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
				handler := http.FileServer(http.Dir(path))
				handler.ServeHTTP(w, r)
			})

			// Determine whether or not a specified node has been processed -- ie if its results are ready to be displayed
			mux.HandleFunc("/checkNode", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
				w.WriteHeader(http.StatusOK)
				found := false
				nodeID, err := ioutil.ReadAll(r.Body)
				if err != nil {
					log.Fatalf("Did not receive node ID: %v", err)
				}
				for _, req := range reqList {
					if string(req.NodeID) == string(nodeID) {
						w.Write([]byte("true"))
						found = true
					}
				}
				if !found {
					w.Write([]byte("false"))
				}
			})
			err = srv.ListenAndServeTLS(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
			if err != nil {
				log.Fatalf("ListenAndServeTLS: %s", err)
			}
			return nil
		},
	}
)
