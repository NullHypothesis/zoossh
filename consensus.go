// Parses files containing network consensuses

package zoossh

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var consensusAnnotations map[Annotation]bool = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"network-status-consensus-3", "1", "0"}: true,
}

type GetStatus func() *RouterStatus

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
	Fingerprint Fingerprint
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

	// Consensus meta information.
	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time

	// A map from relay fingerprint to a function which returns the relay
	// status.
	RouterStatuses map[Fingerprint]GetStatus
}

// String implements the String as well as the Object interface.  It returns
// the status' string representation.
func (s *RouterStatus) String() string {

	return fmt.Sprintf("%s,%s,%s,%d,%d,%s,%s,%s",
		s.Fingerprint,
		s.Nickname,
		s.Address,
		s.ORPort,
		s.DirPort,
		s.Flags,
		s.Publication,
		strings.Replace(s.TorVersion, ",", "", -1))
}

// GetFingerprint implements the Object interface.  It returns the router
// status' fingerprint.
func (s *RouterStatus) GetFingerprint() Fingerprint {

	return s.Fingerprint
}

// Length implements the ObjectSet interface.  It returns the length of the
// consensus.
func (c *Consensus) Length() int {

	return len(c.RouterStatuses)
}

// Iterate implements the ObjectSet interface.  Using a channel, it iterates
// over and returns all router statuses.
func (c *Consensus) Iterate() <-chan Object {

	ch := make(chan Object)

	go func() {
		for _, getVal := range c.RouterStatuses {
			ch <- getVal()
		}
		close(ch)
	}()

	return ch
}

// GetObject implements the ObjectSet interface.  It returns the object
// identified by the given fingerprint.  If the object is not present in the
// set, false is returned, otherwise true.
func (c *Consensus) GetObject(fingerprint Fingerprint) (Object, bool) {

	return c.Get(fingerprint)
}

// Merge merges the given object set with itself.
func (c *Consensus) Merge(objs ObjectSet) {

	for obj := range objs.Iterate() {
		fpr := obj.GetFingerprint()
		_, exists := c.Get(fpr)
		if !exists {
			c.Set(fpr, obj.(*RouterStatus))
		}
	}
}

// NewConsensus serves as a constructor and returns a pointer to a freshly
// allocated and empty Consensus.
func NewConsensus() *Consensus {

	return &Consensus{RouterStatuses: make(map[Fingerprint]GetStatus)}
}

// ToSlice converts the given consensus to a slice.  Consensus meta information
// is lost.
func (c *Consensus) ToSlice() []GetStatus {

	length := c.Length()
	statuses := make([]GetStatus, length)

	i := 0
	for _, getStatus := range c.RouterStatuses {
		statuses[i] = getStatus
		i += 1
	}

	return statuses
}

// Get returns the router status for the given fingerprint and a boolean value
// indicating if the status could be found in the consensus.
func (c *Consensus) Get(fingerprint Fingerprint) (*RouterStatus, bool) {

	getStatus, exists := c.RouterStatuses[SanitiseFingerprint(fingerprint)]
	if !exists {
		return nil, exists
	}

	return getStatus(), exists
}

// Set adds a new fingerprint mapping to a function returning the router status
// to the consensus.
func (c *Consensus) Set(fingerprint Fingerprint, status *RouterStatus) {

	c.RouterStatuses[SanitiseFingerprint(fingerprint)] = func() *RouterStatus {
		return status
	}
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

	return fmt.Sprintf(strings.Join(stringFlags, "|"))
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
func LazyParseRawStatus(rawStatus string) (Fingerprint, GetStatus, error) {

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
			return SanitiseFingerprint(Fingerprint(fingerprint)), getStatus, err
		}
	}

	return "", nil, fmt.Errorf("Could not extract relay fingerprint.")
}

// ParseRawStatus parses a raw router status (in string format) and returns the
// router's fingerprint, a function which returns a RouterStatus, and an error
// if there were any during parsing.
func ParseRawStatus(rawStatus string) (Fingerprint, GetStatus, error) {

	var status *RouterStatus = new(RouterStatus)

	lines := strings.Split(rawStatus, "\n")

	// Go over raw statuses line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		switch words[0] {

		case "r":
			status.Nickname = words[1]
			fingerprint, err := Base64ToString(words[2])
			if err != nil {
				return "", nil, err
			}
			status.Fingerprint = SanitiseFingerprint(Fingerprint(fingerprint))

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

// extractStatusEntry extracts the first network status entry from the given
// string blurb.  If successful, it returns the status entry as a string and
// true or false, depending on if it extracted the last entry in the string
// blurb or not.
func extractStatusEntry(blurb string) (string, bool, error) {

	start := strings.Index(blurb, "\nr ")
	if start == -1 {
		return "", false, fmt.Errorf("Cannot find beginning of status entry: \"\\nr \"")
	}

	end := strings.Index(blurb[start+1:], "\nr ")
	if end == -1 {
		end := strings.Index(blurb[start+1:], "directory-signature")
		if end == -1 {
			return "", false, fmt.Errorf("Cannot find the end of status entry: \"\\nr \" or \"directory-signature\"")
		}
		return blurb[start : start+end], true, nil
	}

	return blurb[start : start+end], false, nil
}

// extractMetainfo extracts meta information of the open consensus document
// (such as its validity times) and writes it to the provided consensus struct.
func extractMetaInfo(fd *os.File, consensus *Consensus) error {

	var err error

	before, err := fd.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}
	// Later reset fd position because bufio.Scanner reads ahead.
	defer fd.Seek(before, os.SEEK_SET)

	scanner := bufio.NewScanner(fd)

	extractTime := func() (time.Time, error) {
		scanner.Scan()
		line := scanner.Text()
		words := strings.Split(line, " ")
		return time.Parse("2006-01-02 15:04:05", strings.Join(words[1:], " "))
	}

	// The given file descriptor points to the beginning of the file.  Skip
	// lines until we arrive at the consensus times.
	for i := 0; i < 4; i++ {
		scanner.Scan()
	}

	if consensus.ValidAfter, err = extractTime(); err != nil {
		return err
	}
	if consensus.FreshUntil, err = extractTime(); err != nil {
		return err
	}
	if consensus.ValidUntil, err = extractTime(); err != nil {
		return err
	}

	return nil
}

// parseConsensusFile parses the given file and returns a network consensus if
// parsing was successful.  If there were any errors, an error string is
// returned.  If the lazy argument is set to true, parsing of the router
// statuses is delayed until they are accessed.
func parseConsensusFile(fileName string, lazy bool) (*Consensus, error) {

	var consensus = NewConsensus()
	var statusParser func(string) (Fingerprint, GetStatus, error)

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

	err = extractMetaInfo(fd, consensus)
	if err != nil {
		return nil, err
	}

	// We will read raw router statuses from this channel.
	queue := make(chan QueueUnit)
	go DissectFile(fd, extractStatusEntry, queue)

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

		consensus.RouterStatuses[SanitiseFingerprint(fingerprint)] = getStatus
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
