package audit

import (
	"github.com/docker/engine-api/client"
	)


type Result struct {
	Name   string
	Status string
	Output string
}

type Check func(client *client.Client) Result
