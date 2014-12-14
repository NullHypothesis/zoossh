// Parses files containing network consensuses

package zoossh

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// The beginning of a new router status.
	statusDelimiter string = "\nr "
	// The file format we currently (try to) support.
	supportedStatusType  string = "network-status-consensus-3"
	supportedStatusMajor string = "1"
	supportedStatusMinor string = "0"
)

type RouterFlags struct {
	Authority bool
	BadExit   bool
	Exit      bool
	Fast      bool
	Guard     bool
	HSDir     bool
	Named     bool
	Stable    bool
	Running   bool
	Unnamed   bool
	Valid     bool
	V2Dir     bool
}

type RouterStatus struct {

	// The single fields of an "r" line.
	Nickname    string
	Fingerprint string
	Digest      string
	Publication time.Time
	Address     string
	ORPort      uint16
	DirPort     uint16

	// The single fields of an "s" line.
	Flags RouterFlags

	// The single fields of a "v" line.
	TorVersion string

	// The single fields of a "w" line.
	Bandwidth  uint64
	Measured   uint64
	Unmeasured bool

	// The single fields of a "p" line.
	Accept   bool
	PortList string
}

// Implement the Stringer interface for pretty printing.
func (flags RouterFlags) String() string {

	var stringFlags []string

	if flags.Authority {
		stringFlags = append(stringFlags, "Authority")
	}
	if flags.BadExit {
		stringFlags = append(stringFlags, "BadExit")
	}
	if flags.Exit {
		stringFlags = append(stringFlags, "Exit")
	}
	if flags.Fast {
		stringFlags = append(stringFlags, "Fast")
	}
	if flags.Guard {
		stringFlags = append(stringFlags, "Guard")
	}
	if flags.HSDir {
		stringFlags = append(stringFlags, "HSDir")
	}
	if flags.Named {
		stringFlags = append(stringFlags, "Named")
	}
	if flags.Stable {
		stringFlags = append(stringFlags, "Stable")
	}
	if flags.Running {
		stringFlags = append(stringFlags, "Running")
	}
	if flags.Unnamed {
		stringFlags = append(stringFlags, "Unnamed")
	}
	if flags.Valid {
		stringFlags = append(stringFlags, "Valid")
	}
	if flags.V2Dir {
		stringFlags = append(stringFlags, "V2Dir")
	}

	return fmt.Sprintf(strings.Join(stringFlags, ", "))
}

// Implement the Stringer interface for pretty printing.
func (status RouterStatus) String() string {

	fmtString := "\nNickname: %s\nAddress: %s:%d\nFingerprint: %s\n" +
		"Flags: %s\nDir port: %d\nPublished: %s\nVersion: %s\n"

	return fmt.Sprintf(fmtString,
		status.Nickname,
		status.Address,
		status.ORPort,
		strings.ToUpper(status.Fingerprint),
		status.Flags,
		status.DirPort,
		status.Publication,
		status.TorVersion)
}

func parseRouterFlags(flags []string) *RouterFlags {

	var routerFlags *RouterFlags = new(RouterFlags)

	for _, flag := range flags {
		switch flag {
		case "Authority":
			routerFlags.Authority = true
		case "BadExit":
			routerFlags.BadExit = true
		case "Exit":
			routerFlags.Exit = true
		case "Fast":
			routerFlags.Fast = true
		case "Guard":
			routerFlags.Guard = true
		case "HSDir":
			routerFlags.HSDir = true
		case "Named":
			routerFlags.Named = true
		case "Stable":
			routerFlags.Stable = true
		case "Running":
			routerFlags.Running = true
		case "Unnamed":
			routerFlags.Unnamed = true
		case "Valid":
			routerFlags.Valid = true
		case "V2Dir":
			routerFlags.V2Dir = true
		}
	}

	return routerFlags
}

// Parses a raw router status (in string format) and returns the status as a
// RouterStatus struct.  If there were any errors during parsing, an error
// string is returned.
func ParseRawStatus(rawStatus string) (*RouterStatus, error) {

	var status *RouterStatus = new(RouterStatus)
	var err error

	lines := strings.Split(rawStatus, "\n")

	// Go over raw statuses line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		switch words[0] {

		case "r":
			status.Nickname = words[1]
			status.Fingerprint, err = Base64ToString(words[2])
			if err != nil {
				return nil, err
			}

			status.Digest, err = Base64ToString(words[3])
			if err != nil {
				return nil, err
			}

			time, _ := time.Parse(publishedTimeLayout, strings.Join(words[4:6], " "))
			status.Publication = time
			status.Address = words[6]
			status.ORPort = StringToPort(words[7])
			status.DirPort = StringToPort(words[8])

		case "s":
			status.Flags = *parseRouterFlags(words[1:])

		case "v":
			status.TorVersion = words[2]

		case "w":
			bwExpr := words[1]
			values := strings.Split(bwExpr, "=")
			status.Bandwidth, _ = strconv.ParseUint(values[1], 10, 64)

		case "p":
			if words[1] == "accept" {
				status.Accept = true
			} else {
				status.Accept = false
			}
			status.PortList = strings.Join(words[2:], " ")
		}
	}

	return status, nil
}

// Parses the given file and returns a slice of RouterStatus structs is parsing
// was successful.  If there were any errors, an error string is returned.
func ParseConsensusFile(fileName string) ([]RouterStatus, error) {

	var statuses []RouterStatus

	// Check if the file's annotation is as expected.
	expected := &Annotation{
		supportedStatusType,
		supportedStatusMajor,
		supportedStatusMinor,
	}
	err := CheckAnnotation(fileName, expected)
	if err != nil {
		return nil, err
	}

	// We will read raw router statuses from this channel.
	queue := make(chan QueueUnit)

	go DissectFile(fileName, Delimiter{"\nr ", 1}, queue)

	// Parse incoming router statuses until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.Err != nil {
			return nil, unit.Err
		}

		status, err := ParseRawStatus(unit.Blurb)
		if err != nil {
			return nil, err
		}

		statuses = append(statuses, *status)
	}

	return statuses, nil
}
