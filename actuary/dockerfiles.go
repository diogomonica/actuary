/*
Package checks - 3 Docker daemon configuration files
This section covers Docker related files and directory permissions and ownership. Keeping
the files and directories, that may contain sensitive parameters, secure is important for
correct and secure functioning of Docker daemon.
*/
package actuary

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func CheckServiceOwner(t Target) (res Result) {
	res.Name = "3.1 Verify that docker.service file ownership is set to root:root"
	fileInfo, err := lookupFile("docker.service", systemdPaths)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}

	refUID, refGID := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)

	if (refUID == fileUID) && (refGID == fileGID) {
		res.Pass()
	} else {
		output := fmt.Sprintf("User/group owner should be : %s", "root")
		res.Fail(output)
	}
	return
}

func CheckServicePerms(t Target) (res Result) {
	res.Name = `3.2 Verify that docker.service file permissions are set to
		644 or more restrictive`
	var refPerms uint32 = 0644
	fileInfo, err := lookupFile("docker.service", systemdPaths)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckSocketOwner(t Target) (res Result) {
	res.Name = "3.3 Verify that docker.socket file ownership is set to root:root"
	fileInfo, err := lookupFile("docker.socket", systemdPaths)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, refGID := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGID == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "root")
	}
	return res
}

func CheckSocketPerms(t Target) (res Result) {
	res.Name = `3.4 Verify that docker.socket file permissions are set to 644 or more
        restrictive`
	var refPerms uint32 = 0644
	fileInfo, err := lookupFile("docker.socket", systemdPaths)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckDockerDirOwner(t Target) (res Result) {
	res.Name = "3.5 Verify that /etc/docker directory ownership is set to root:root "
	fileInfo, err := os.Stat("/etc/docker")
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, refGid := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "root")
	}
	return res
}

func CheckDockerDirPerms(t Target) (res Result) {
	res.Name = `3.6 Verify that /etc/docker directory permissions
		are set to 755 or more restrictive`
	var refPerms uint32 = 0644
	fileInfo, err := os.Stat("/etc/docker")
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckRegistryCertOwner(t Target) (res Result) {
	var badFiles []string
	res.Name = `3.7 Verify that registry certificate file ownership
	 is set to root:root`
	refUID, refGid := getUserInfo("root")
	files, err := ioutil.ReadDir("/etc/docker/cert.d")
	if err != nil {
		res.Status = "INFO"
		res.Output = fmt.Sprintf("Directory is inaccessible")
		return res
	}
	for _, file := range files {
		fmt.Println(file.Name())
		if file.IsDir() {
			log.Printf("FILENAME: %s", file.Name())
			certs, err := ioutil.ReadDir(file.Name()) //DOES THIS WORK
			if err != nil {
				log.Fatal(err)
			}
			for _, cert := range certs {
				if err != nil {
					log.Fatal(err)
				}
				fileUID, fileGID := getFileOwner(cert)
				if (refUID != fileUID) || (refGid != fileGID) {
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
			"root", badFiles)
	}
	return res
}

func CheckRegistryCertPerms(t Target) (res Result) {
	var badFiles []string
	var refPerms uint32
	res.Name = `3.8 Verify that registry certificate file permissions
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

func CheckCACertOwner(t Target) (res Result) {
	res.Name = "3.9 Verify that TLS CA certificate file ownership is set to root:root"
	certPath := t.CertPath("docker", "--tlscacert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, refGid := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "root")
	}
	return res
}

func CheckCACertPerms(t Target) (res Result) {
	res.Name = `3.10 Verify that TLS CA certificate file permissions
	are set to 444 or more restrictive`
	var refPerms uint32 = 0644
	certPath := t.CertPath("docker", "--tlscacert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckServerCertOwner(t Target) (res Result) {
	res.Name = `3.11 Verify that Docker server certificate file ownership is set to
        root:root`
	certPath := t.CertPath("docker", "--tlscert")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, refGid := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "root")
	}
	return res
}

func CheckServerCertPerms(t Target) (res Result) {
	res.Name = `3.12 Verify that Docker server certificate file permissions
		are set to 444 or more restrictive`
	certPath := t.CertPath("docker", "--tlscert")
	var refPerms uint32 = 0644
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckCertKeyOwner(t Target) (res Result) {
	res.Name = `3.13 Verify that Docker server certificate key file ownership is set to
        root:root`
	certPath := t.CertPath("docker", "--tlskey")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, refGid := getUserInfo("root")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "root")
	}
	return res
}

func CheckCertKeyPerms(t Target) (res Result) {
	res.Name = `3.14 Verify that Docker server certificate key file
	permissions are set to 400`
	var refPerms uint32 = 0644
	certPath := t.CertPath("docker", "--tlskey")
	fileInfo, err := os.Stat(certPath)
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckDockerSockOwner(t Target) (res Result) {
	res.Name = `3.15 Verify that Docker socket file ownership
	is set to root:docker`
	fileInfo, err := os.Stat("/var/run/docker.sock")
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, _ := getUserInfo("root")
	refGid := getGroupID("docker")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Status = "PASS"
	} else {
		res.Status = "WARN"
		res.Output = fmt.Sprintf("User/group owner should be : %s", "docker")
	}
	return res
}

func CheckDockerSockPerms(t Target) (res Result) {
	res.Name = `3.16 Verify that Docker socket file permissions are set to 660`
	fileInfo, err := os.Stat("/var/run/docker.sock")
	var refPerms uint32 = 0644
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
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

func CheckDaemonJSONOwner(t Target) (res Result) {
	res.Name = `3.17 Verify that daemon.json file ownership is set to root:root`
	fileInfo, err := os.Stat("/etc/docker/daemon.json")
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, _ := getUserInfo("root")
	refGid := getGroupID("docker")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Pass()
	} else {
		output := fmt.Sprintf("User/group owner should be : %s", "docker")
		res.Fail(output)
	}
	return
}

func CheckDaemonJSONPerms(t Target) (res Result) {
	res.Name = `3.18 Verify that daemon.json file permissions are set to 644 or more
restrictive`
	fileInfo, err := os.Stat("/etc/docker/daemon.json")
	var refPerms uint32 = 0644
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Pass()
	} else {
		output := fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
		res.Fail(output)
	}
	return
}

func CheckDefaultOwner(t Target) (res Result) {
	res.Name = `3.19 Verify that /etc/default/docker file ownership is set to root:root`
	fileInfo, err := os.Stat("/etc/default/docker")
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	refUID, _ := getUserInfo("root")
	refGid := getGroupID("docker")
	fileUID, fileGID := getFileOwner(fileInfo)
	if (refUID == fileUID) && (refGid == fileGID) {
		res.Pass()
	} else {
		output := fmt.Sprintf("User/group owner should be : %s", "docker")
		res.Fail(output)
	}
	return
}

func CheckDefaultPerms(t Target) (res Result) {
	res.Name = `3.20 Verify that /etc/default/docker file permissions are set to 644 or
more restrictive`
	fileInfo, err := os.Stat("/etc/default/docker")
	var refPerms uint32 = 0644
	if os.IsNotExist(err) {
		res.Skip("File could not be accessed")
		return
	}
	isLeast, perms := hasLeastPerms(fileInfo, refPerms)
	if isLeast == true {
		res.Pass()
	} else {
		output := fmt.Sprintf("File has less restrictive permissions than expected: %v",
			perms)
		res.Fail(output)
	}
	return
}
