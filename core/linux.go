package core

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

const (
	passwdPath = "/etc/passwd"
	shadowPath = "/etc/shadow"
	rootPath   = "/"
)

var (
	sad = aurora.Red("SAD")
	res = aurora.Green("YAY")
	bsh = aurora.Cyan("CMD")
)

func LinPrivEscChecker() {

	//Task 2
	time.Sleep(3 * time.Second)
	fmt.Println("=============== Service Exploit ====================")
	gologger.Info().Msg("Checking if MySQL running as root ↓")
	checkMySQLProcess()

	//Task 3
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Readable /etc/shadow ===============")
	gologger.Info().Msg("Checking if Shadow file is world-readable ↓")
	checkShadowReadable()

	//Task 4
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Writable /etc/shadow ===============")
	gologger.Info().Msg("Checking if Shadow file is world-writable ↓")
	checkShadowWritable()

	//Task 5
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Writable /etc/passwd ===============")
	gologger.Info().Msg("Checking if Passwd file is world-writable ↓")
	checkPasswdWritable()

	//Task 6
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Sudo - Shell Escape ===============")
	gologger.Info().Msg("Running sudo -l ↓")
	checkSudoCommands()

	//Task 7
	fmt.Println("\n=============== Sudo - Environment Variable ===============")
	gologger.Info().Msg("Listing environment variable and shell escape ↓")
	checkShellEscapePath()

	//Task 9
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Cron Jobs PATH ===============")
	gologger.Info().Msg("Checking cronjobs environment PATH ↓")
	checkCronjobsPath()

	//Task 8
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== Cron Jobs File ===============")
	gologger.Info().Msg("Checking cronjobs ↓")
	checkCronJobs()

	//Task 10
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Cron Jobs Wildcard ===============")
	gologger.Info().Msg("Need to manually check the content if cron jobs script (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `cat /etc/crontab`")

	//Task 11
	time.Sleep(3 * time.Second)
	fmt.Println("\n=============== SUID/SGID Known Exploits ===============")
	gologger.Info().Msg("Listing SUID/SGID Executable ↓")
	checkSuidExec()

	//Task 12
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== SUID/SGID Known Shared Object Injection ===============")
	gologger.Info().Msg("Need to manually verify which SUID/SGID executable is vulnerable to shared object injection (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null`")

	//Task 13
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== SUID/SGID Known Environment Variables ===============")
	gologger.Info().Msg("Need to manually verify which SUID/SGID executable is vulnerable to environment variable (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null`")

	//Task 14
	//Task 15
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== SUID/SGID Known Abusing shell ===============")
	gologger.Info().Msg("Need to manually verify which SUID/SGID executable can be abused to pop shell (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null`")

	//Task 16
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Passwords & Keys - History Files ===============")
	gologger.Info().Msg("Need to manually verify password or key files (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `cat ~history | less`")

	//Task 17
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Passwords & Keys - Config Files ===============")
	gologger.Info().Msg("Need to manually find config/password file (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `find /etc -name \"*.conf\" -o -name \"*.cfg\" -o -name \"*.config\"`")

	//Task 18
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Passwords & Keys - SSH Keys ===============")
	gologger.Info().Msg("Need to manually find ssh private key (if any) ↓")
	gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `ls -la / OR ls -la /.ssh OR ls -la ~/.ssh`")

	//Task 19
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Network File System ===============")
	gologger.Info().Msg("Checking for NFS share configuration ↓")
	checkNFS()

	//Task 20
	time.Sleep(2 * time.Second)
	fmt.Println("\n=============== Kernel Exploits ===============")
	gologger.Info().Msg("Checking for possible kernel exploit ↓")
	checkKernel()

}

// Mysql running as root
func checkMySQLProcess() {
	// Mysql running as root
	cmdMysql := exec.Command("bash", "-c", "pgrep mysql | xargs ps -fp | awk '{print $1}'")

	// Capture the output
	output, errMysql := cmdMysql.Output()

	if errMysql != nil {
		gologger.Error().Msgf("Error grabbing the mysql process: %s", errMysql)
		os.Exit(1)
	}

	// Convert the output to string
	outputString := string(output)
	lines := strings.Split(outputString, "\n")

	if len(lines) >= 2 {
		// Get the second line
		uid := strings.TrimSpace(lines[1])

		// Check if UID is root
		if uid == "root" {
			gologger.Print().Label(res.String()).Msg("The mysql was running as root")
			gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `pgrep mysql | xargs ps -fp | awk '{print $1}'`")
		} else {
			gologger.Print().Label(sad.String()).Msg("The mysql was not running as root")
		}
	} else {
		gologger.Print().Label(sad.String()).Msg("Mysql process information was not found")
	}
}

// World-Readable func
func isWorldReadable(filePath string) (bool, error) {
	// Get file information
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}

	// Extract permission bits
	permissions := fileInfo.Mode().Perm()

	// Check if others (world) have read permission
	worldReadable := permissions&(1<<2) != 0

	return worldReadable, nil
}

// World-Writable func
func isWorldWritable(filePath string) (bool, error) {
	// Get file information
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}

	// Extract permission bits
	permissions := fileInfo.Mode().Perm()

	// Check if others (world) have write permission
	worldWritable := permissions&(1<<1) != 0

	return worldWritable, nil
}

// Readable /etc/shadow
func checkShadowReadable() {

	shadowReadable, errShadowReadable := isWorldReadable(shadowPath)
	if errShadowReadable != nil {
		gologger.Error().Msgf("Error checking world readability: %s", errShadowReadable)
		return
	}
	if shadowReadable {
		gologger.Print().Label(res.String()).Msg("Shadow file is world-readable")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `ls -lat /etc/shadow`")
	} else {
		gologger.Print().Label(sad.String()).Msg("Shadow file is not world-readable")
	}
}

// Writable /etc/shadow
func checkShadowWritable() {

	shadowWritable, errShadowWritable := isWorldWritable(shadowPath)
	if errShadowWritable != nil {
		gologger.Error().Msgf("Error checking world writability: %s", errShadowWritable)
		return
	}
	if shadowWritable {
		gologger.Print().Label(res.String()).Msg("Shadow file is world-writable")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `ls -lat /etc/shadow`")
	} else {
		gologger.Print().Label(sad.String()).Msg("Shadow file is not world-writable")
	}
}

// Writable /etc/passwd
func checkPasswdWritable() {

	passwdWritable, errPasswdWritable := isWorldWritable(passwdPath)
	if errPasswdWritable != nil {
		gologger.Error().Msgf("Error checking world writability: %s", errPasswdWritable)
		return
	}
	if passwdWritable {
		gologger.Print().Label(res.String()).Msg("Passwd file is world-writable")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `ls -lat /etc/passwd`")
	} else {
		gologger.Print().Label(sad.String()).Msg("Passwd file is not world-writable")
	}
}

func checkSudoCommands() {
	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		gologger.Error().Msgf("Error: %s", err)
		return
	}

	// Run sudo -l command
	cmdSudo := exec.Command("sudo", "-l")

	// Capture the output
	output, err := cmdSudo.Output()
	if err != nil {
		fmt.Println("Error running sudo -l:", err)
		return
	}

	// Convert the output to string
	outputString := string(output)

	// Split the output into lines
	lines := strings.Split(outputString, "\n")

	errorMessage := fmt.Sprintf("%s is not in the sudoers file.  This incident will be reported.", currentUser.Username)

	// Flag to indicate whether the common part is printed
	commonPartPrinted := false

	// Print lines containing "(root) NOPASSWD:"
	for _, line := range lines {
		if strings.Contains(line, "(root) NOPASSWD:") {
			if !commonPartPrinted {
				gologger.Print().Label(res.String()).Msg("Listing out all the executables")
				commonPartPrinted = true
			}
			fmt.Println(line)
		} else if strings.Contains(line, "(ALL : ALL) ALL") {
			if !commonPartPrinted {
				gologger.Print().Label(res.String()).Msg("Able to run all")
				commonPartPrinted = true
			}
			fmt.Println(line)
		} else if strings.Contains(line, errorMessage) {
			gologger.Print().Label(sad.String()).Msg("Error sending command `sudo -l`")
		}
	}
}

func checkShellEscapePath() {
	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		gologger.Error().Msgf("Error: %s", err)
		return
	}

	// Run sudo -l command
	cmdSudoPath := exec.Command("sudo", "-l")

	// Capture the output
	output, errSudoPath := cmdSudoPath.Output()
	if errSudoPath != nil {
		fmt.Println("Error running sudo -l:", errSudoPath)
		return
	}

	pattern := fmt.Sprintf(`(?s)Matching Defaults entries for %s on this host:(.*?)(?:may run the following commands on this host:|$)`, currentUser.Username)

	// Convert the output to string
	outputString := string(output)

	re := regexp.MustCompile(pattern)

	// Use regular expression to extract the relevant part
	matches := re.FindStringSubmatch(outputString)

	if len(matches) >= 2 {
		// Trim leading and trailing whitespaces
		result := strings.TrimSpace(matches[1])
		fmt.Println(result)
	} else {
		fmt.Println("No matching defaults found")
	}
}

func checkCronJobs() {
	content, err := os.ReadFile("/etc/crontab")
	if err != nil {
		gologger.Error().Msgf("Error reading /etc/crontab: %s", err)
		return
	}

	gologger.Print().Label(res.String()).Msg("Content of /etc/crontab")
	// Convert content to string
	crontabContent := string(content)

	// Split the content into lines
	lines := strings.Split(crontabContent, "\n")

	// Print non-comment lines
	for _, line := range lines {
		// Skip lines starting with #
		if strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Println(line)
	}
}

// Check cronjobs PATH if it contain $HOME
func checkCronjobsPath() {
	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		gologger.Error().Msgf("Error: %s", err)
		return
	}

	// Read the contents of /etc/crontab
	crontabContent, err := os.ReadFile("/etc/crontab")
	if err != nil {
		gologger.Error().Msgf("Error reading /etc/crontab: %s", err)
		return
	}

	// Convert the content to string
	crontabString := string(crontabContent)

	// Find the line with "PATH=" in /etc/crontab
	pathLine := ""
	for _, line := range strings.Split(crontabString, "\n") {
		if strings.HasPrefix(line, "PATH=") {
			pathLine = line
			break
		}
	}

	// Check if the home directory is in the PATH
	if strings.Contains(pathLine, currentUser.HomeDir) {
		gologger.Print().Label(res.String()).Msg("PATH in /etc/crontab has home user directory")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `cat /etc/crontab`")
	} else {
		gologger.Print().Label(sad.String()).Msg("PATH in /etc/crontab does not have home user directory")
	}
}

// find suid
func checkSuidExec() {
	// find / -type f -a ( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
	cmd := exec.Command("sh", "-c", "find / -type f \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2>/dev/null")
	output, err := cmd.CombinedOutput()
	if err != nil {
		gologger.Error().Msgf("Error %s", string(output))
		return
	}
	fmt.Println(string(output))
}

// nfs
func checkNFS() {
	// check the NFS share configuration
	cmd := exec.Command("sh", "-c", "cat /etc/exports")
	output, err := cmd.CombinedOutput()
	if err != nil {
		gologger.Error().Msgf("Error %s", string(output))
		return
	}
	if strings.Contains(string(output), "No such file") {
		gologger.Print().Label(sad.String()).Msg("Exports not found")
	} else {
		gologger.Print().Label(res.String()).Msg("Reading exports file")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `cat /etc/crontab`")
		fmt.Println(string(output))
	}
}

// kernel
func checkKernel() {
	// CVE-2022-0847
	checkCve220847()

	// TODO other kernel exploit
}

func checkCve220847() {
	cmd := exec.Command("bash", "-c", "uname -a | awk '{print $3}'")
	output, err := cmd.Output()
	if err != nil {
		gologger.Error().Msgf("Error running command: %s", err)
		return
	}

	kernelVersion := strings.TrimSpace(string(output))
	gologger.Info().Msgf("Kernel Version: %s", kernelVersion)
	fmt.Println()

	vulnerableRangeStart := "5.8.0"
	vulnerableRangeEnd := "5.16.11"
	patchVersions := []string{"5.16.11", "5.15.25", "5.10.102"}

	if isVulnerable(kernelVersion, vulnerableRangeStart, vulnerableRangeEnd, patchVersions) {
		gologger.Print().Label(res.String()).Msg("Kernel version MIGHT be vulnerable to CVE-2022-0847")
		gologger.Print().Label(bsh.String()).Msg("Check out this command to verify! `uname -a | awk '{print $3}'`")
	} else {
		gologger.Print().Label(sad.String()).Msg("Kernel version was either not vulnerable or patched for CVE-2022-0847.")
	}
}

func isVulnerable(version, rangeStart, rangeEnd string, patchVersions []string) bool {
	if compareVersions(version, rangeStart) >= 0 && compareVersions(version, rangeEnd) < 0 {
		return true
	}

	for _, patchVersion := range patchVersions {
		if version == patchVersion {
			return false // It's a patch version
		}
	}

	return false
}

func compareVersions(a, b string) int {
	// Split version strings into arrays of integers
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	// Compare each part of the version
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if aParts[i] > bParts[i] {
			return 1
		} else if aParts[i] < bParts[i] {
			return -1
		}
	}

	// If all parts are equal, compare the length
	return len(aParts) - len(bParts)
}

func splitVersion(version string) []int {
	var parts []int
	for _, part := range strings.Split(version, ".") {
		var num int
		_, err := fmt.Sscanf(part, "%d", &num)
		if err == nil {
			parts = append(parts, num)
		}
	}
	return parts
}
