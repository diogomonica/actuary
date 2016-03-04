package dockerfiles

import (
	"fmt"
	"github.com/diogomonica/actuary/audit"
	"github.com/docker/engine-api/client"
	"log"
	"os"
	"os/user"
	"syscall"
)

var checks = map[string]audit.Check{
	"docker.service_perms":          CheckServicePerms,
	"docker.service_owner":          CheckServiceOwner,
	"docker-registry.service_owner": CheckRegistryOwner,
	"docker-registry.service_perms": CheckRegistryPerms,
}

func GetAuditDefinitions() map[string]audit.Check {

	return checks
}

func hasLeastPerms(info os.FileInfo, safePerms uint32) (isLeast bool, perms os.FileMode) {
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

func getFileOwner(info os.FileInfo) (uid, gid string) {

	uid = fmt.Sprint(info.Sys().(*syscall.Stat_t).Uid)
	gid = fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid)

	return uid, gid
}

func CheckServiceOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.1 Verify that docker.service file ownership is set to root:root"
	filename := "/lib/systemd/system/docker.service"
	refUser := "root"
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File %s could not be accessed", filename)
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
	res.Name = `3.2 Verify that docker.service file permissions are set to 644 or more
	 restrictive`
	filename := "/lib/systemd/system/docker.service"
	refPerms = 0644
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File %s could not be accessed", filename)
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v", perms)
	}

	return res
}

func CheckRegistryOwner(client *client.Client) audit.Result {
	var res audit.Result
	res.Name = "3.3 Verify that docker-registry.service file ownership is set to root:root "
	filename := "/lib/systemd/system/docker-registry.service"
	refUser := "root"
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File %s could not be accessed", filename)
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
	res.Name = `3.4 Verify that docker-registry.service file permissions are set to 644 or
	 more restrictive`
	filename := "/lib/systemd/system/docker-registry.service"
	refPerms = 0644
	fileInfo, err := os.Stat(filename)
	if os.IsNotExist(err) {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("File %s could not be accessed", filename)
		return res
	}

	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("File has less restrictive permissions than expected: %v", perms)
	}

	return res
}
