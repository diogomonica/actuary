package audit

import (
	"github.com/docker/engine-api/client"
	"github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/process"
	"strings"
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
	proc, err := process.NewProcess(int32(pid))
	cmd, err = proc.CmdlineSlice()
	return cmd, err
}

func GetCmdOption(args []string, opt string) (exist bool, val string) {
	var optBuf string
	for _, arg := range args {
		if strings.Contains(arg, opt) {
			optBuf = arg
			exist = true
			break
		}
	}
	if exist {
		nameVal := strings.Split(optBuf, "=")
		if len(nameVal) > 1 {
			val = strings.TrimSuffix(nameVal[1], " ")
		}
	} else {
		exist = false
	}

	return exist, val
}
