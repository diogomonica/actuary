package main

import (
	"github.com/diogomonica/actuary/cmd/actuary/check"
	"github.com/diogomonica/actuary/cmd/actuary/server"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	//This seems problematic -- fix this
	if c, err := mainCmd.ExecuteC(); err != nil {
		c.Println("Error:", grpc.ErrorDesc(err))
		// if it's not a grpc, we assume it's a user error and we display the usage.
		if grpc.Code(err) == codes.Unknown {
			c.Println(c.UsageString())
		}

		os.Exit(-1)
	}
}
