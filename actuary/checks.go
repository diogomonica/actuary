package actuary

import (
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/context"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

// Result objects are returned from Check functions
type Result struct {
	Name   string
	Status string
	Output string
}

// Skip is used when a check won't run. Output is used to describe the reason.
func (r *Result) Skip(s string) {
	r.Status = "SKIP"
	r.Output = s
	return
}

// Pass is used when a check has passed
func (r *Result) Pass() {
	r.Status = "PASS"
	return
}

// Fail is used when a check has failed. Output is used to describe the reason.
func (r *Result) Fail(s string) {
	r.Status = "WARN"
	r.Output = s
	return
}

// Info is used when a test will not pass nor fail
func (r *Result) Info(s string) {
	r.Status = "INFO"
	r.Output = s
	return
}

//Check
type Check func(t Target) Result

var checklist = map[string]Check{
	//Docker Host
	"separate_partition": CheckSeparatePartition,
	"kernel_version":     CheckKernelVersion,
	"running_services":   CheckRunningServices,
	"server_version":     CheckDockerVersion,
	"trusted_users":      CheckTrustedUsers,
	"audit_daemon":       AuditDockerDaemon,
	"audit_lib":          AuditLibDocker,
	"audit_etc":          AuditEtcDocker,
	"audit_service":      AuditDockerService,
	"audit_socket":       AuditDockerSocket,
	"audit_default":      AuditDockerDefault,
	"audit_daemonjson":   AuditDaemonJSON,
	"audit_containerd":   AuditContainerd,
	"audit_runc":         AuditRunc,
	//Docker Files
	"docker.service_perms": CheckServicePerms,
	"docker.service_owner": CheckServiceOwner,
	"docker.socket_owner":  CheckSocketOwner,
	"docker.socket_perms":  CheckSocketPerms,
	"dockerdir_owner":      CheckDockerDirOwner,
	"dockerdir_perms":      CheckDockerDirPerms,
	"registrycerts_owner":  CheckRegistryCertOwner,
	"registrycerts_perms":  CheckRegistryCertPerms,
	"cacert_owner":         CheckCACertOwner,
	"cacert_perms":         CheckCACertPerms,
	"servercert_owner":     CheckServerCertOwner,
	"servercert_perms":     CheckServerCertPerms,
	"certkey_owner":        CheckCertKeyOwner,
	"certkey_perms":        CheckCertKeyPerms,
	"socket_owner":         CheckDockerSockOwner,
	"socket_perms":         CheckDockerSockPerms,
	"daemonjson_owner":     CheckDaemonJSONOwner,
	"daemonjson_perms":     CheckDaemonJSONPerms,
	"dockerdef_owner":      CheckDefaultOwner,
	"dockerdef_perms":      CheckDefaultPerms,
	//Docker Configuration
	"net_traffic":       RestrictNetTraffic,
	"logging_level":     CheckLoggingLevel,
	"allow_iptables":    CheckIpTables,
	"insecure_registry": CheckInsecureRegistry,
	"aufs_driver":       CheckAufsDriver,
	"tls_auth":          CheckTLSAuth,
	"default_ulimit":    CheckUlimit,
	"user_namespace":    CheckUserNamespace,
	"default_cgroup":    CheckDefaultCgroup,
	"device_size":       CheckBaseDevice,
	"auth_plugin":       CheckAuthPlugin,
	"central_logging":   CheckCentralLogging,
	"legacy_registry":   CheckLegacyRegistry,
	//Docker Container Images
	"root_containers": CheckContainerUser,
	"content_trust":   CheckContentTrust,
	//Docker Container Runtime
	"apparmor_profile":      CheckAppArmor,
	"selinux_options":       CheckSELinux,
	"kernel_capabilities":   CheckKernelCapabilities,
	"privileged_containers": CheckPrivContainers,
	"sensitive_dirs":        CheckSensitiveDirs,
	"ssh_running":           CheckSSHRunning,
	"privileged_ports":      CheckPrivilegedPorts,
	"needed_ports":          CheckNeededPorts,
	"host_net_mode":         CheckHostNetworkMode,
	"memory_usage":          CheckMemoryLimits,
	"cpu_shares":            CheckCPUShares,
	"readonly_rootfs":       CheckReadonlyRoot,
	"bind_specific_int":     CheckBindHostInterface,
	"restart_policy":        CheckRestartPolicy,
	"host_namespace":        CheckHostNamespace,
	"ipc_namespace":         CheckIPCNamespace,
	"host_devices":          CheckHostDevices,
	"override_ulimit":       CheckDefaultUlimit,
	"mount_propagation":     CheckMountPropagation,
	"uts_namespace":         CheckUTSnamespace,
	"seccomp_profile":       CheckSeccompProfile,
	"cgroup_usage":          CheckCgroupUsage,
	"add_privs":             CheckAdditionalPrivs,
	//Docker Security Operations
	"image_sprawl":     CheckImageSprawl,
	"container_sprawl": CheckContainerSprawl,
}

type ContainerInfo struct {
	types.ContainerJSON
}

type Container struct {
	ID   string
	Info ContainerInfo
}

type ContainerList []Container

func (l *ContainerList) Running() bool {
	if len(*l) != 0 {
		return true
	}
	return false
}

//RunCheck returns a list of containers that failed the check
func (l *ContainerList) runCheck(r *Result, f func(c ContainerInfo) bool, msg string) {
	var badContainers []string
	for _, container := range *l {
		if f(container.Info) == false {
			badContainers = append(badContainers, container.ID+" ")
		}
	}
	if len(badContainers) == 0 {
		r.Pass()
	} else {
		output := fmt.Sprintf(msg,
			badContainers)
		r.Fail(output)
	}
	return
}

//Target stores information regarding the audit's target Docker server
type Target struct {
	Client     *client.Client
	Info       types.Info
	Containers ContainerList
	ProcFunc   func(procname string) (cmd []string, err error)
	CertPath   func(procname string, tlsOpt string) (val string)
	BaseDir    string
}

//NewTarget initiates a new Target struct
func NewTarget() (a Target, err error) {
	a.Client, err = client.NewEnvClient()
	if err != nil {
		log.Fatalf("unable to create Docker client: %v\n", err)
	}
	a.Info, err = a.Client.Info(context.TODO())
	if err != nil {
		log.Fatalf("unable to fetch Docker daemon INFO: %v\n", err)
	}
	err = a.createContainerList()
	a.ProcFunc = getProcCmdline
	a.CertPath = getCertPath
	a.BaseDir = ""
	return
}

func (t *Target) createContainerList() error {
	opts := types.ContainerListOptions{All: true}
	containers, err := t.Client.ContainerList(context.Background(), opts)
	if err != nil {
		log.Fatalf("unable to get container list: %v\n", err)
	}
	for _, cont := range containers {
		entry := new(Container)
		inspectData, _ := t.Client.ContainerInspect(context.TODO(), cont.ID)
		info := &ContainerInfo{inspectData}
		entry.ID = cont.ID
		entry.Info = *info
		t.Containers = append(t.Containers, *entry)
	}
	return nil
}

var systemdPaths = []string{"/usr/lib/systemd/system/",
	"/lib/systemd/system/",
	"/etc/systemd/system/",
	"/etc/sysconfig/",
	"/etc/default/",
	"/etc/docker",
}

func GetAuditDefinitions() map[string]Check {
	return checklist
}

type auditdError struct {
	Error   error
	Message string
	Code    int //1: Cannot read auditd rules. 2: Rule does not exist
}

// Returns the PID of a given process name
func getProcPID(proc string) (pid int) {
	ps, _ := ps.Processes()
	for i := range ps {
		if ps[i].Executable() == proc {
			pid = ps[i].Pid()
		}
	}
	return pid
}

// Returns the command line slice for a given process name
func getProcCmdline(procname string) (cmd []string, err error) {
	var proc *process.Process
	pid := getProcPID(procname)
	proc, err = process.NewProcess(int32(pid))
	cmd, err = proc.CmdlineSlice()
	return cmd, err
}

func getCertPath(procname string, tlsOpt string) (val string) {
	dockerProc, _ := getProcCmdline(procname)
	_, certPath := getCmdOption(dockerProc, tlsOpt)
	return certPath
}

// Checks if a command-line slice contains a given option and returns its value
func getCmdOption(args []string, opt string) (exist bool, val string) {
	exist = false
	for _, arg := range args {
		if strings.Contains(arg, opt) {
			exist = true
			nameVal := strings.Split(arg, "=")
			if len(nameVal) > 1 {
				val = strings.TrimSuffix(nameVal[1], " ")
			}
			break
		}
	}
	return exist, val
}

// Searches for a filename in given dirs
func lookupFile(filename string, dirs []string) (info os.FileInfo, err error) {
	for _, path := range dirs {
		fullPath := filepath.Join(path, filename)
		info, err = os.Stat(fullPath)
		if err == nil {
			return
		}
	}
	return
}

func hasLeastPerms(info os.FileInfo, safePerms uint32) (isLeast bool,
	perms os.FileMode) {
	mode := info.Mode().Perm()
	if uint32(mode) <= safePerms {
		isLeast = true
	} else {
		isLeast = false
	}
	return isLeast, mode
}

// Returns UID, GID for a username
func getUserInfo(username string) (uid, gid string) {
	userInfo, err := user.Lookup(username)
	if err != nil {
		log.Printf("Username %s not found", username)
	}
	uid = userInfo.Uid
	gid = userInfo.Gid
	return uid, gid
}

// Returns GID for a given group
func getGroupID(groupname string) string {
	groupFile, err := ioutil.ReadFile("/etc/group")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(groupFile), "\n") {
		items := strings.Split(line, ":")
		if groupname == items[0] {
			gid := items[2]
			return gid
		}
	}
	return ""
}

func getFileOwner(info os.FileInfo) (uid, gid string) {
	uid = fmt.Sprint(info.Sys().(*syscall.Stat_t).Uid)
	gid = fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid)
	return uid, gid
}

// Looks for the path of an executable, runs it with options/args and returns output
func getCmdOutput(exe string, opts ...string) (output []byte, err error) {
	exePath, err := exec.LookPath(exe)
	if err != nil {
		log.Printf("could not find executable: %v", err)
		return
	}
	cmd := exec.Command(exePath, strings.Join(opts, " "))
	output, err = cmd.Output()
	if err != nil {
		log.Printf("unable to execute command: %v", err)
	}
	return
}

// Helper function to check rules in auditctl
// If expected output changes, make sure to change the data in testdata
func checkAuditRule(rule string) *auditdError {
	output, err := getCmdOutput("auditctl", "-l")
	if err != nil {
		return &auditdError{err, "Unable to retrieve rule list", 1}
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, rule) {
			return nil
		}
	}
	return &auditdError{nil, "Rule not found", 2}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
