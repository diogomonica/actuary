package audit

import (
	"github.com/docker/engine-api/client"
	"github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/process"
	//"log"
	)


type Result struct {
	Name   string
	Status string
	Output string
}

type Check func(client *client.Client) Result

func GetProcCmdline(procname string) (cmd []string, err error) {
	var pid int

	ps, _ := ps.Processes()
	for i, _ := range ps {
		if ps[i].Executable() == procname {
			pid = ps[i].Pid()
			break
		}
	}
	proc,err := process.NewProcess(int32(pid))
	cmd, err = proc.CmdlineSlice()
	return cmd, err
}