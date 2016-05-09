package checks

import (
	"strings"

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

//Skip is used when a check won't run. Output is used to describe the reason.
func (r *Result) Skip(s string) {
	r.Status = "SKIP"
	r.Output = s
	return
}

//Pass is used when a check has passed
func (r *Result) Pass() {
	r.Status = "PASS"
	return
}

//Fail is used when a check has failed. Output is used to describe the reason.
func (r *Result) Fail(s string) {
	r.Status = "WARN"
	r.Output = s
	return
}

func (r *Result) Info(s string) {
	r.Status = "INFO"
	r.Output = s
	return
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
