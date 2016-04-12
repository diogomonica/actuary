package dockerfiles

import (
	"fmt"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

var checks = map[string]audit.Check{
	"docker.service_perms":          CheckServicePerms,
	"docker.service_owner":          CheckServiceOwner,
	"docker-registry.service_owner": CheckRegistryOwner,
	"docker-registry.service_perms": CheckRegistryPerms,
	"docker.socket_owner":           CheckSocketOwner,
	"docker.socket_perms":           CheckSocketPerms,
	"dockerenv_owner":               CheckEnvOwner,
	"dockerenv_perms":               CheckEnvPerms,
	"docker-network_owner":          CheckNetEnvOwner,
	"docker-network_perms":          CheckNetEnvPerms,
	"docker-registry_owner":         CheckRegEnvOwner,
	"docker-registry_perms":         CheckRegEnvPerms,
	"docker-storage_owner":          CheckStoreEnvOwner,
	"docker-storage_perms":          CheckStoreEnvPerms,
	"dockerdir_owner":               CheckDockerDirOwner,
	"dockerdir_perms":               CheckDockerDirPerms,
	"registrycerts_owner":           CheckRegistryCertOwner,
	"registrycerts_perms":           CheckRegistryCertPerms,
	"cacert_owner":                  CheckCACertOwner,
	"cacert_perms":                  CheckCACertPerms,
	"servercert_owner":              CheckServerCertOwner,
	"servercert_perms":              CheckServerCertPerms,
	"certkey_owner":                 CheckCertKeyOwner,
	"certkey_perms":                 CheckCertKeyPerms,
	"socket_owner":                  CheckDockerSockOwner,
	"socket_perms":                  CheckDockerSockPerms,
}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
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

func CheckServiceOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.1 Verify that docker.service file ownership is set to root:root"
	refUser := "root"
	fileInfo, err := getSystemdFile("docker.service")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckServicePerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.2 Verify that docker.service file permissions are set to 
		644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker.service")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckRegistryOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.3 Verify that docker-registry.service file ownership is set 
	to root:root`
	refUser := "root"
	fileInfo, err := getSystemdFile("docker-registry.service")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckRegistryPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.4 Verify that docker-registry.service file permissions 
		are set to 644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker-registry.service")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckSocketOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.5 Verify that docker.socket file ownership is set to root:root"
	refUser := "root"
	fileInfo, err := getSystemdFile("docker.socket")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckSocketPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.6 Verify that docker.socket file permissions are set to 644 or more
        restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker.socket")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckEnvOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.7 Verify that Docker environment file ownership 
		is set to root:root`
	refUser := "root"
	fileInfo, err := getSystemdFile("docker")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckEnvPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.8 Verify that Docker environment file permissions are set 
		to 644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckNetEnvOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.9 Verify that docker-network environment file ownership is set to
        root:root`
	refUser := "root"
	fileInfo, err := getSystemdFile("docker-network")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckNetEnvPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.10 Verify that docker-network environment file permissions are set to
        644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker-network")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckRegEnvOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.11 Verify that docker-registry environment file ownership is set to
        root:root`
	refUser := "root"
	fileInfo, err := getSystemdFile("docker-registry")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckRegEnvPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.12 Verify that docker-registry environment file permissions 
	are set to 644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker-registry")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckStoreEnvOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.13 Verify that docker-storage environment file ownership is set to
        root:root`
	refUser := "root"
	fileInfo, err := getSystemdFile("docker-storage")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s",
			refUser)
	}

	return res
}

func CheckStoreEnvPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.14 Verify that docker-storage environment file permissions 
		are set to 644 or more restrictive`
	refPerms = 0644
	fileInfo, err := getSystemdFile("docker-storage")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckDockerDirOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.15 Verify that /etc/docker directory ownership is set to root:root "
	refUser := "root"
	fileInfo, err := os.Stat("/etc/docker")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckDockerDirPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.16 Verify that /etc/docker directory permissions 
		are set to 755 or more restrictive`
	refPerms = 0755
	fileInfo, err := os.Stat("/etc/docker")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckRegistryCertOwner(client *client.Client) audit.Result {
	var res audit.Result
	var badFiles []string
	res.Name = `3.17 Verify that registry certificate file ownership
	 is set to root:root`
	refUser := "root"
	refUid, refGid := getUserInfo(refUser)

	files, err := ioutil.ReadDir("/etc/docker/certs.d/")
	if err != nil {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("Directory is inaccessible")
		return res
	}
	for _, file := range files {
		fmt.Println(file.Name())
		if file.IsDir() {
			certs, err := ioutil.ReadDir(file.Name())
			if err != nil {
				log.Fatal(err)
			}
			for _, cert := range certs {
				if err != nil {
					log.Fatal(err)
				}
				fileUid, fileGid := getFileOwner(cert)
				if (refUid != fileUid) || (refGid != fileGid) {
					badFiles = append(badFiles, cert.Name())
				}
			}
		}
	}
	if len(badFiles) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Certificate files do not have %s as owner : %s",
			refUser, badFiles)
	}
	return res
}

func CheckRegistryCertPerms(client *client.Client) audit.Result {
	var res audit.Result
	var badFiles []string
	var refPerms uint32
	res.Name = `3.18 Verify that registry certificate file permissions 
		are set to 444 or more restrictive`
	refPerms = 0444
	files, err := ioutil.ReadDir("/etc/docker/certs.d/")
	if err != nil {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("Directory is inaccessible")
		return res
	}
	for _, file := range files {
		fmt.Println(file.Name())
		if file.IsDir() {
			certs, err := ioutil.ReadDir(file.Name())
			if err != nil {
				log.Fatal(err)
			}
			for _, cert := range certs {
				if err != nil {
					log.Fatal(err)
				}
				isLeast, _ := hasLeastPerms(cert, refPerms)
				if isLeast == false {
					badFiles = append(badFiles, cert.Name())
				}
			}
		}
	}
	if len(badFiles) == 0 {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("Certificate files do not have required permissions: %s",
			badFiles)
	}
	return res
}

func CheckCACertOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.19 Verify that TLS CA certificate file ownership is set to root:root"
	refUser := "root"
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlscacert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckCACertPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.20 Verify that TLS CA certificate file permissions 
	are set to 444 or more restrictive`
	refPerms = 0444
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlscacert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckServerCertOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.21 Verify that Docker server certificate file ownership is set to
        root:root`
	refUser := "root"
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlscert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckServerCertPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.22 Verify that Docker server certificate file permissions 
		are set to 444 or more restrictive`
	refPerms = 0444
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlscert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckCertKeyOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.23 Verify that Docker server certificate key file ownership is set to
        root:root`
	refUser := "root"
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlskey")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, refGid := getUserInfo(refUser)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refUser)
	}

	return res
}

func CheckCertKeyPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.24 Verify that Docker server certificate key file 
	permissions are set to 400`
	refPerms = 0400
	dockerProc, _ := audit.GetProcCmdline("docker")
	_, certPath := audit.GetCmdOption(dockerProc, "--tlskey")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}

func CheckDockerSockOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = `3.25 Verify that Docker socket file ownership 
	is set to root:docker`
	refUser := "root"
	refGroup := "docker"
	fileInfo, err := os.Stat("/var/run/docker.sock")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	refUid, _ := getUserInfo(refUser)
	refGid := getGroupId(refGroup)
	fileUid, fileGid := getFileOwner(fileInfo)
	if (refUid == fileUid) && (refGid == fileGid) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", refGroup)
	}

	return res
}

func CheckDockerSockPerms(client *client.Client) audit.Result {
	var res audit.Result
	var refPerms uint32
	res.Name = `3.26 Verify that Docker socket file permissions are set to 660`
	refPerms = 0660
	fileInfo, err := os.Stat("/var/run/docker.sock")
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File could not be accessed")
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
	}

	return res
}
