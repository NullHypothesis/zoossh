// Parses files containing network consensuses

package zoossh

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var consensusAnnotations = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"network-status-consensus-3", "1", "0"}: true,
}

var bridgeNetworkStatusAnnotations = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"bridge-network-status", "1", "2"}: true,
}

var ErrNoStatusEntry = fmt.Errorf("cannot find the end of status entry: \"\\nr \" or \"directory-signature\"")

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

type RouterAddress struct {
	IPv4Address net.IP
	IPv4ORPort  uint16
	IPv4DirPort uint16

	IPv6Address net.IP
	IPv6ORPort  uint16
}

type RouterStatus struct {

	// The single fields of an "r" line.
	Nickname    string
	Fingerprint Fingerprint
	Digest      string
	Publication time.Time

	// The IPv4 and IPv6 fields of "a" line
	Address RouterAddress

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
	// Generic map of consensus metadata
	MetaInfo map[string][]byte

	// Document validity period
	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time

	// Shared randomness
	SharedRandPrevious []byte
	SharedRandCurrent  []byte

	// A map from relay fingerprint to a function which returns the relay
	// status.
	RouterStatuses map[Fingerprint]GetStatus
}

// String implements the String as well as the Object interface.  It returns
// the status' string representation.
func (s *RouterStatus) String() string {

	return fmt.Sprintf("%s,%s,%+v,%s,%s,%s",
		s.Fingerprint,
		s.Nickname,
		s.Address,
		s.Flags,
		s.Publication.Format(time.RFC3339),
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
// over and returns all router statuses.  The given object filter can be used
// to filter router statuses, e.g., by fingerprint.
func (c *Consensus) Iterate(filter *ObjectFilter) <-chan Object {

	ch := make(chan Object)

	go func() {
		for _, getStatus := range c.RouterStatuses {
			status := getStatus()
			if filter == nil || filter.IsEmpty() || filter.MatchesRouterStatus(status) {
				ch <- status
			}
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

	for obj := range objs.Iterate(nil) {
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
		i++
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
func (c *Consensus) Subtract(b *Consensus) *Consensus {

	var remainder = NewConsensus()

	for fingerprint, getStatus := range c.RouterStatuses {

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
func (c *Consensus) Intersect(b *Consensus) *Consensus {

	var intersection = NewConsensus()

	for fingerprint, getStatus := range c.RouterStatuses {

		_, exists := b.RouterStatuses[fingerprint]
		if exists {
			intersection.RouterStatuses[fingerprint] = getStatus
		}
	}

	return intersection
}

// Implement the Stringer interface for pretty printing.
func (address RouterAddress) String() string {
	var ipV4stringAddress []string
	var ipV6stringAddress []string

	if address.IPv4Address != nil {
		ipV4stringAddress = append(ipV4stringAddress, address.IPv4Address.String())
	}
	ipV4stringAddress = append(ipV4stringAddress, fmt.Sprintf("%v", address.IPv4ORPort))
	ipV4stringAddress = append(ipV4stringAddress, fmt.Sprintf("%v", address.IPv4DirPort))
	ipV4Join := fmt.Sprint(strings.Join(ipV4stringAddress, "|"))

	if address.IPv6Address == nil {
		return ipV4Join
	}

	ipV6stringAddress = append(ipV6stringAddress, address.IPv6Address.String())
	ipV6stringAddress = append(ipV6stringAddress, fmt.Sprintf("%v", address.IPv6ORPort))

	ipV6Join := fmt.Sprint(strings.Join(ipV6stringAddress, "|"))
	return ipV4Join + "," + ipV6Join
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

	return fmt.Sprint(strings.Join(stringFlags, "|"))
}

func parseRouterFlags(flags []string) *RouterFlags {

	var routerFlags = new(RouterFlags)

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

func parseIPv6AddressAndPort(addressAndPort string) (address net.IP, port uint16) {
	var ipV6regex = regexp.MustCompile(`\[(.*?)\]`)
	var ipV6portRegex = regexp.MustCompile(`\]:(.*)`)
	address = net.ParseIP(ipV6regex.FindStringSubmatch(addressAndPort)[1])
	port = StringToPort(ipV6portRegex.FindStringSubmatch(addressAndPort)[1])

	return address, port
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

	return "", nil, fmt.Errorf("could not extract relay fingerprint")
}

// ParseRawStatus parses a raw router status (in string format) and returns the
// router's fingerprint, a function which returns a RouterStatus, and an error
// if there were any during parsing.
func ParseRawStatus(rawStatus string) (Fingerprint, GetStatus, error) {

	var status = new(RouterStatus)

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
			status.Address.IPv4Address = net.ParseIP(words[6])
			status.Address.IPv4ORPort = StringToPort(words[7])
			status.Address.IPv4DirPort = StringToPort(words[8])

		case "a":
			status.Address.IPv6Address, status.Address.IPv6ORPort = parseIPv6AddressAndPort(words[1])

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

// extractStatusEntry is a bufio.SplitFunc that extracts individual network
// status entries.
func extractStatusEntry(data []byte, atEOF bool) (advance int, token []byte, err error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	start := 0
	if !bytes.HasPrefix(data, []byte("r ")) {
		start = bytes.Index(data, []byte("\nr "))
		if start < 0 {
			if atEOF {
				return 0, nil, fmt.Errorf("cannot find beginning of status entry: \"\\nr \"")
			}
			// Request more data.
			return 0, nil, nil
		}
		start++
	}

	end := bytes.Index(data[start:], []byte("\nr "))
	if end >= 0 {
		return start + end + 1, data[start : start+end+1], nil
	}
	end = bytes.Index(data[start:], []byte("directory-signature"))
	if end >= 0 {
		// "directory-signature" means this is the last status; stop
		// scanning.
		return start + end, data[start : start+end], bufio.ErrFinalToken
	}
	if atEOF {
		return len(data), data[start:], ErrNoStatusEntry
	}
	// Request more data.
	return 0, nil, nil
}

// extractMetainfo extracts meta information of the open consensus document
// (such as its validity times) and writes it to the provided consensus struct.
// It assumes that the type annotation has already been read.
func extractMetaInfo(br *bufio.Reader, c *Consensus) error {

	c.MetaInfo = make(map[string][]byte)

	// Read the initial metadata. We'll later extract information of particular
	// interest by name. The weird Reader loop is because scanner reads too much.
	for line, err := br.ReadSlice('\n'); ; line, err = br.ReadSlice('\n') {
		if err != nil {
			return err
		}

		// splits to (key, value)
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return errors.New("malformed metainfo line")
		}

		key := string(split[0])
		c.MetaInfo[key] = bytes.TrimSpace(split[1])

		// Look ahead to check if we've reached the end of the unique keys.
		nextKey, err := br.Peek(11)
		if err != nil {
			return err
		}
		if bytes.HasPrefix(nextKey, []byte("dir-source")) || bytes.HasPrefix(nextKey, []byte("fingerprint")) {
			break
		}
	}

	var err error
	// Define a parser for validity timestamps
	parseTime := func(line []byte) (time.Time, error) {
		return time.Parse("2006-01-02 15:04:05", string(line))
	}

	// Extract the validity period of this consensus
	c.ValidAfter, err = parseTime(c.MetaInfo["valid-after"])
	if err != nil {
		return err
	}
	c.FreshUntil, err = parseTime(c.MetaInfo["fresh-until"])
	if err != nil {
		return err
	}
	c.ValidUntil, err = parseTime(c.MetaInfo["valid-until"])
	if err != nil {
		return err
	}

	// Reads a shared-rand line from the consensus and returns decoded bytes.
	parseRand := func(line []byte) ([]byte, error) {
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return nil, errors.New("malformed shared random line")
		}
		// should split to (vote count, b64 bytes)
		_, rand := split[0], split[1]
		return base64.StdEncoding.DecodeString(string(rand))
	}

	// Only the newer consensus documents have these values.
	if line, ok := c.MetaInfo["shared-rand-previous-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.SharedRandPrevious = val
	}
	if line, ok := c.MetaInfo["shared-rand-current-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.SharedRandCurrent = val
	}

	return nil
}

// MatchesRouterStatus returns true if fields of the given router status are
// present in the object filter, e.g., the router's nickname is part of the
// object filter.
func (filter *ObjectFilter) MatchesRouterStatus(status *RouterStatus) bool {

	if filter.HasIPAddr(status.Address.IPv4Address) || (filter.HasIPAddr(status.Address.IPv6Address)) {
		return true
	}

	if filter.HasFingerprint(status.Fingerprint) {
		return true
	}

	if filter.HasNickname(status.Nickname) {
		return true
	}

	return false
}

// parseConsensusUnchecked parses a descriptor of type
// "network-status-consensus-3".  The input should be without a type annotation;
// i.e., the type annotation should already have been read and checked to be the
// correct type.  The function returns a network consensus if parsing was
// successful.  If there were any errors, an error string is returned.  If the
// lazy argument is set to true, parsing of the router statuses is delayed until
// they are accessed. If strict it will only accept valid consensus files, not
// strict is used to parse bridge networkstatus files or when unknown what kind is.
func parseConsensusUnchecked(r io.Reader, lazy bool, strict bool) (*Consensus, error) {

	var consensus = NewConsensus()
	var statusParser func(string) (Fingerprint, GetStatus, error)

	if lazy {
		statusParser = LazyParseRawStatus
	} else {
		statusParser = ParseRawStatus
	}

	br := bufio.NewReader(r)
	err := extractMetaInfo(br, consensus)
	if strict && err != nil {
		return nil, err
	}

	// We will read raw router statuses from this channel.
	queue := make(chan QueueUnit)
	go DissectFile(br, extractStatusEntry, queue)

	// Parse incoming router statuses until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.Err != nil && (strict || !errors.Is(unit.Err, ErrNoStatusEntry)) {
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

// parseConsensus is a wrapper around parseConsensusUnchecked that first reads
// and checks the type annotation to make sure it belongs to
// consensusAnnotations.
func parseConsensus(r io.Reader, lazy bool) (*Consensus, error) {

	strict := false
	annotation, r, err := readAnnotation(r)
	if err != nil {
		return nil, err
	}
	if _, ok := consensusAnnotations[*annotation]; ok {
		strict = true
	} else if _, ok := bridgeNetworkStatusAnnotations[*annotation]; !ok {
		return nil, fmt.Errorf("unexpected file annotation: %s", annotation)
	}

	return parseConsensusUnchecked(r, lazy, strict)
}

// parseConsensusFile is a wrapper around parseConsensus that opens the named
// file for parsing.
func parseConsensusFile(fileName string, lazy bool) (*Consensus, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return parseConsensus(fd, lazy)
}

// parseConsensusFileUnchecked is a wrapper around parseConsensusUnchecked that opens the named
// file for parsing.
func parseConsensusFileUnchecked(fileName string, lazy bool) (*Consensus, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return parseConsensusUnchecked(fd, lazy, false)
}

// ParseRawConsensus parses a raw consensus (in string format) and
// returns a network consensus if parsing was successful.
func ParseRawConsensus(rawConsensus string, lazy bool) (*Consensus, error) {
	r := strings.NewReader(rawConsensus)

	return parseConsensus(r, lazy)
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

// ParseRawUnsafeConsensus parses a raw consensus (in string format) and
// returns a network consensus if parsing was successful.
func ParseRawUnsafeConsensus(rawConsensus string, lazy bool) (*Consensus, error) {
	r := strings.NewReader(rawConsensus)

	return parseConsensusUnchecked(r, lazy, false)
}

// LazilyParseUnsafeConsensusFile parses the given file without checking the
// annotations and returns a network consensus if parsing was successful. If
// there were any errors, consensus if parsing was successful.  If there were
// any errors, an error string is returned.  Parsing of the router statuses is
// delayed until they are accessed using the Get method.  As a result, this
// function is recommended as long as you won't access more than ~50% of all
// statuses.
func LazilyParseUnsafeConsensusFile(fileName string) (*Consensus, error) {

	return parseConsensusFileUnchecked(fileName, true)
}

// ParseUnsafeConsensusFile parses the given file without checking the annotations
// and returns a network consensus if parsing was successful. If there were any
// errors, an error string is returned.  In contrast to LazilyParseConsensusFile,
// parsing of router statuses is *not* delayed.  As a result, this function is
// recommended as long as you will access most of all statuses.
func ParseUnsafeConsensusFile(fileName string) (*Consensus, error) {

	return parseConsensusFileUnchecked(fileName, false)
}
