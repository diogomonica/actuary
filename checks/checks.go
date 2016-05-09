package checks

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/docker/engine-api/client"
	"github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/process"
)

//Check
type Check func(client *client.Client) Result

//Result objects are returned from Check functions
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

// Info is used when a test will not pass nor fail
func (r *Result) Info(s string) {
	r.Status = "INFO"
	r.Output = s
	return
}

var checklist = map[string]Check{
	//Docker Host
	"kernel_version":     CheckKernelVersion,
	"separate_partition": CheckSeparatePartion,
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
	//Docker Configuration
	"net_traffic":       RestrictNetTraffic,
	"logging_level":     CheckLoggingLevel,
	"allow_iptables":    CheckIpTables,
	"insecure_registry": CheckInsecureRegistry,
	"aufs_driver":       CheckAufsDriver,
	"tls_auth":          CheckTLSAuth,
	"default_ulimit":    CheckUlimit,
	//Docker Container Images
	"root_containers": CheckContainerUser,
	//Docker Container Runtime
	"apparmor_profile":      CheckAppArmor,
	"selinux_options":       CheckSELinux,
	"single_process":        CheckSingleMainProcess,
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
	//Docker Security Operations
	"central_logging":  CheckCentralLogging,
	"container_sprawl": CheckContainerSprawl,
}

func GetAuditDefinitions() map[string]Check {

	return checklist
}

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

func getSystemdFile(filename string) (info os.FileInfo, err error) {
	var systemdPath string
	knownPaths := []string{"/usr/lib/systemd/system/",
		"/lib/systemd/system/",
		"/etc/systemd/system/",
		"/etc/sysconfig/",
		"/etc/default/",
		"/etc/docker",
	}

	for _, path := range knownPaths {
		systemdPath = filepath.Join(path, filename)
		info, err = os.Stat(systemdPath)
		if err == nil {
			return info, err
		}
	}
	return info, err
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

func getUserInfo(username string) (uid, gid string) {
	userInfo, err := user.Lookup(username)
	if err != nil {
		log.Printf("Username %s not found", username)
	}
	uid = userInfo.Uid
	gid = userInfo.Gid

	return uid, gid
}

func getGroupId(groupname string) string {
	bytes, err := ioutil.ReadFile("/etc/group")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(bytes), "\n") {
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

//Helper function to check rules in auditctl
func checkAuditRule(rule string) bool {
	auditctlPath, err := exec.LookPath("auditctl")
	if err != nil || auditctlPath == "" {
		log.Panicf("Could not find auditctl tool")
	}
	cmd := exec.Command(auditctlPath, "-l")
	output, err := cmd.Output()
	if err != nil {
		log.Panicf("Auditctl command returned with errors")
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, rule) {
			return true
		}
	}
	return false
}
