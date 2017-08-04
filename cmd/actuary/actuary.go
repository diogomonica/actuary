package main

import (
	"github.com/diogomonica/actuary/cmd/actuary/check"
	"github.com/diogomonica/actuary/cmd/actuary/server"
	"github.com/spf13/cobra"
	"os"
)

var (
	mainCmd = &cobra.Command{
		Use:           os.Args[0],
		Short:         "Run actuary on a swarm",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
)

func init() {
	mainCmd.AddCommand(
		server.ServerCmd,
		check.CheckCmd,
	)
}

func main() {
	if c, err := mainCmd.ExecuteC(); err != nil {
		c.Println("Error:", err)
		os.Exit(-1)
	}
}
