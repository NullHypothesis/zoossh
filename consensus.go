// Parses files containing network consensuses

package zoossh

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// The beginning of a new router status.
	statusDelimiter string = "\nr "
)

var consensusAnnotations map[Annotation]bool = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"network-status-consensus-3", "1", "0"}: true,
}

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
	Address     net.IP
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

type Consensus struct {

	// A map from relay fingerprint to a function which returns the relay
	// status.
	RouterStatuses map[string]func() *RouterStatus
}

// NewConsensus serves as a constructor and returns a pointer to a freshly
// allocated and empty Consensus.
func NewConsensus() *Consensus {

	return &Consensus{RouterStatuses: make(map[string]func() *RouterStatus)}
}

// Get returns the router status for the given fingerprint and a boolean value
// indicating if the status could be found in the consensus.
func (c *Consensus) Get(fingerprint string) (*RouterStatus, bool) {

	getStatus, exists := c.RouterStatuses[strings.ToUpper(fingerprint)]
	if !exists {
		return nil, exists
	}

	return getStatus(), exists
}

// Set adds a new fingerprint mapping to a function returning the router status
// to the consensus.
func (c *Consensus) Set(fingerprint string, status *RouterStatus) {

	c.RouterStatuses[strings.ToUpper(fingerprint)] = func() *RouterStatus {
		return status
	}
}

// Length returns the length of the consensus.
func (c *Consensus) Length() int {

	return len(c.RouterStatuses)
}

// Subtract removes all routers which are part of the given consensus b from
// consensus a.  It returns a new consensus which is the result of the
// subtraction.
func (a *Consensus) Subtract(b *Consensus) *Consensus {

	var remainder = NewConsensus()

	for fingerprint, getStatus := range a.RouterStatuses {

		_, exists := b.RouterStatuses[fingerprint]
		if !exists {
			remainder.RouterStatuses[fingerprint] = getStatus
		}
	}

	return remainder
}

// Intersect determines the intersection between the given consensus b and
// consensus a.  It returns a new consensus which is the intersection of both
// given consensuses.
func (a *Consensus) Intersect(b *Consensus) *Consensus {

	var intersection = NewConsensus()

	for fingerprint, getStatus := range a.RouterStatuses {

		_, exists := b.RouterStatuses[fingerprint]
		if exists {
			intersection.RouterStatuses[fingerprint] = getStatus
		}
	}

	return intersection
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

// LazyParseRawStatus parses a raw router status (in string format) and returns
// the router's fingerprint, a function which returns a RouterStatus, and an
// error if there were any during parsing.  Parsing of the given string is
// delayed until the returned function is executed.
func LazyParseRawStatus(rawStatus string) (string, func() *RouterStatus, error) {

	// Delay parsing of the router status until this function is executed.
	getStatus := func() *RouterStatus {
		_, f, _ := ParseRawStatus(rawStatus)
		return f()
	}

	lines := strings.Split(rawStatus, "\n")

	// Only pull out the fingerprint.
	for _, line := range lines {
		words := strings.Split(line, " ")
		if words[0] == "r" {
			fingerprint, err := Base64ToString(words[2])
			return fingerprint, getStatus, err
		}
	}

	return "", nil, fmt.Errorf("Could not extract relay fingerprint.")
}

// ParseRawStatus parses a raw router status (in string format) and returns the
// router's fingerprint, a function which returns a RouterStatus, and an error
// if there were any during parsing.
func ParseRawStatus(rawStatus string) (string, func() *RouterStatus, error) {

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
				return "", nil, err
			}

			status.Digest, err = Base64ToString(words[3])
			if err != nil {
				return "", nil, err
			}

			time, _ := time.Parse(publishedTimeLayout, strings.Join(words[4:6], " "))
			status.Publication = time
			status.Address = net.ParseIP(words[6])
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

	return status.Fingerprint, func() *RouterStatus { return status }, nil
}

// parseConsensusFile parses the given file and returns a network consensus if
// parsing was successful.  If there were any errors, an error string is
// returned.  If the lazy argument is set to true, parsing of the router
// statuses is delayed until they are accessed.
func parseConsensusFile(fileName string, lazy bool) (*Consensus, error) {

	var consensus = NewConsensus()
	var statusParser func(string) (string, func() *RouterStatus, error)

	if lazy {
		statusParser = LazyParseRawStatus
	} else {
		statusParser = ParseRawStatus
	}

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	err = CheckAnnotation(fd, consensusAnnotations)
	if err != nil {
		return nil, err
	}

	// We will read raw router statuses from this channel.
	queue := make(chan QueueUnit)

	go DissectFile(fd, Delimiter{"\nr ", 1, 1}, queue)

	// Parse incoming router statuses until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.Err != nil {
			return nil, unit.Err
		}

		fingerprint, getStatus, err := statusParser(unit.Blurb)
		if err != nil {
			return nil, err
		}

		consensus.RouterStatuses[strings.ToUpper(fingerprint)] = getStatus
	}

	return consensus, nil
}

// LazilyParseConsensusFile parses the given file and returns a network
// consensus if parsing was successful.  If there were any errors, an error
// string is returned.  Parsing of the router statuses is delayed until they
// are accessed using the Get method.  As a result, this function is
// recommended as long as you won't access more than ~50% of all statuses.
func LazilyParseConsensusFile(fileName string) (*Consensus, error) {

	return parseConsensusFile(fileName, true)
}

// ParseConsensusFile parses the given file and returns a network consensus if
// parsing was successful.  If there were any errors, an error string is
// returned.  In contrast to LazilyParseConsensusFile, parsing of router
// statuses is *not* delayed.  As a result, this function is recommended as
// long as you will access most of all statuses.
func ParseConsensusFile(fileName string) (*Consensus, error) {

	return parseConsensusFile(fileName, false)
}
