// Parses files containing network consensuses

package zoossh

import (
	"strconv"
	"strings"
	"time"
	"encoding/base64"
	"encoding/hex"
)

const (
	// The beginning of a new router status.
	statusDelimiter string = "\nr "
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

func ParseRawStatus(rawStatus string) (*RouterStatus, error) {

	var status *RouterStatus = new(RouterStatus)
	var port uint64

	lines := strings.Split(rawStatus, "\n")

	// Go over raw statuses line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		switch words[0] {

		case "r":
			status.Nickname = words[1]
			fpr, _ := base64.StdEncoding.DecodeString(words[2])
			status.Fingerprint = hex.EncodeToString(fpr)
			fpr, _ = base64.StdEncoding.DecodeString(words[3])
			status.Digest = hex.EncodeToString(fpr)
			time, _ := time.Parse(publishedTimeLayout, strings.Join(words[4:6], " "))
			status.Publication = time
			status.Address = words[6]
			port, _ = strconv.ParseUint(words[7], 10, 16)
			status.ORPort = uint16(port)
			port, _ = strconv.ParseUint(words[8], 10, 16)
			status.DirPort = uint16(port)

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

func ParseConsensusFile(fileName string) ([]RouterStatus, error) {

	var statuses []RouterStatus

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
