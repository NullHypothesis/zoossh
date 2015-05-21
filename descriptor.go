// Parses files containing server descriptors.

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
	// The layout of the "published" field.
	publishedTimeLayout string = "2006-01-02 15:04:05"
)

var descriptorAnnotations map[Annotation]bool = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"server-descriptor", "1", "0"}: true,
}

// An exitpattern as defined in dirspec.txt, Section 2.1.3.
type ExitPattern struct {
	AddressSpec string
	PortSpec    string
}

// An (incomplete) router descriptor as defined in dirspec.txt, Section 2.1.1.
type RouterDescriptor struct {

	// The single fields of a "router" line.
	Nickname  string
	Address   net.IP
	ORPort    uint16
	SOCKSPort uint16
	DirPort   uint16

	// The single fields of a "bandwidth" line.  All bandwidth values are in
	// bytes per second.
	BandwidthAvg   uint64
	BandwidthBurst uint64
	BandwidthObs   uint64

	// The single fields of a "platform" line.
	OperatingSystem string
	TorVersion      string

	// The single fields of a "published" line.
	Published time.Time

	// The single fields of an "uptime" line.
	Uptime uint64

	// The single fields of a "fingerprint" line.
	Fingerprint string

	// The single fields of a "hibernating" line.
	Hibernating bool

	// The single fields of a "family" line.
	Family []string

	// The single fields of a "contact" line.
	Contact string

	// The "hidden-service-dir" line.
	HiddenServiceDir bool

	OnionKey     string
	NTorOnionKey string
	SigningKey   string

	Accept []*ExitPattern
	Reject []*ExitPattern
}

type RouterDescriptors struct {

	// A map from relay fingerprint to a function which returns the router
	// descriptor.
	RouterDescriptors map[string]func() *RouterDescriptor
}

// String implements the String as well as the Object interface.  It returns
// the descriptor's string representation.
func (desc *RouterDescriptor) String() string {

	fmtString := "\nNickname: %s\nAddress: %s:%d\nFingerprint: %s\n" +
		"Dir port: %d\nPublished: %s\nUptime: %d\nContact: %s\nOperating " +
		"system: %s\nVersion: %s"

	return fmt.Sprintf(fmtString,
		desc.Nickname,
		desc.Address,
		desc.ORPort,
		desc.Fingerprint,
		desc.DirPort,
		desc.Published,
		desc.Uptime,
		desc.Contact,
		desc.OperatingSystem,
		desc.TorVersion)
}

// GetFingerprint implements the Object interface.  It returns the descriptor's
// fingerprint.
func (desc *RouterDescriptor) GetFingerprint() string {

	return strings.ToUpper(desc.Fingerprint)
}

// Length implements the ObjectSet interface.  It returns the length of the
// router descriptors.
func (descs *RouterDescriptors) Length() int {

	return len(descs.RouterDescriptors)
}

// Iterate implements the ObjectSet interface.  Using a channel, it iterates
// over and returns all router descriptors.
func (descs *RouterDescriptors) Iterate() <-chan Object {

	ch := make(chan Object)

	go func() {
		for _, getVal := range descs.RouterDescriptors {
			ch <- getVal()
		}
		close(ch)
	}()

	return ch
}

// GetObject implements the ObjectSet interface.  It returns the object
// identified by the given fingerprint.  If the object is not present in the
// set, false is returned, otherwise true.
func (desc *RouterDescriptors) GetObject(fingerprint string) (Object, bool) {

	return desc.Get(fingerprint)
}

// NewRouterDescriptors serves as a constructor and returns a pointer to a
// freshly allocated and empty RouterDescriptors struct.
func NewRouterDescriptors() *RouterDescriptors {

	return &RouterDescriptors{RouterDescriptors: make(map[string]func() *RouterDescriptor)}
}

// Get returns the router descriptor for the given fingerprint and a boolean
// value indicating if the descriptor could be found.
func (d *RouterDescriptors) Get(fingerprint string) (*RouterDescriptor, bool) {

	getDescriptor, exists := d.RouterDescriptors[strings.ToUpper(fingerprint)]
	if !exists {
		return nil, exists
	}

	return getDescriptor(), exists
}

// Set adds a new fingerprint mapping to a function returning the router
// descriptor.
func (d *RouterDescriptors) Set(fingerprint string, descriptor *RouterDescriptor) {

	d.RouterDescriptors[strings.ToUpper(fingerprint)] = func() *RouterDescriptor {
		return descriptor
	}
}

// LazyParseRawDescriptor lazily parses a raw router descriptor (in string
// format) and returns the descriptor's fingerprint, a function returning the
// descriptor, and an error if the descriptor could not be parsed.  Parsing is
// delayed until the router descriptor is accessed.
func LazyParseRawDescriptor(rawDescriptor string) (string, func() *RouterDescriptor, error) {

	var fingerprint string

	// Delay parsing of the router descriptor until this function is executed.
	getDescriptor := func() *RouterDescriptor {
		_, f, _ := ParseRawDescriptor(rawDescriptor)
		return f()
	}

	// Only pull out the fingerprint.
	lines := strings.Split(rawDescriptor, "\n")
	for _, line := range lines {
		words := strings.Split(line, " ")
		if words[0] == "opt" {
			words = words[1:]
		}

		if words[0] == "fingerprint" {
			fingerprint = strings.Join(words[1:], "")
			return fingerprint, getDescriptor, nil
		}
	}

	return "", nil, fmt.Errorf("Could not extract descriptor fingerprint.")
}

// ParseRawDescriptor parses a raw router descriptor (in string format) and
// returns the descriptor's fingerprint, a function returning the descriptor,
// and an error if the descriptor could not be parsed.  In contrast to
// LazyParseRawDescriptor, parsing is *not* delayed.
func ParseRawDescriptor(rawDescriptor string) (string, func() *RouterDescriptor, error) {

	var descriptor *RouterDescriptor = new(RouterDescriptor)

	lines := strings.Split(rawDescriptor, "\n")

	// Go over raw descriptor line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		// Ignore lines starting with "opt".
		if words[0] == "opt" {
			words = words[1:]
		}

		switch words[0] {

		case "router":
			descriptor.Nickname = words[1]
			descriptor.Address = net.ParseIP(words[2])
			descriptor.ORPort = StringToPort(words[3])
			descriptor.SOCKSPort = StringToPort(words[4])
			descriptor.DirPort = StringToPort(words[5])

		case "platform":
			descriptor.OperatingSystem = words[4]
			descriptor.TorVersion = words[2]

		case "uptime":
			descriptor.Uptime, _ = strconv.ParseUint(words[1], 10, 64)

		case "published":
			time, _ := time.Parse(publishedTimeLayout, strings.Join(words[1:], " "))
			descriptor.Published = time

		case "fingerprint":
			descriptor.Fingerprint = strings.Join(words[1:], "")

		case "hibernating":
			descriptor.Hibernating, _ = strconv.ParseBool(words[1])

		case "bandwidth":
			descriptor.BandwidthAvg, _ = strconv.ParseUint(words[1], 10, 64)
			descriptor.BandwidthBurst, _ = strconv.ParseUint(words[2], 10, 64)
			descriptor.BandwidthObs, _ = strconv.ParseUint(words[3], 10, 64)

		case "family":
			descriptor.Family = words[1:]

		case "contact":
			descriptor.Contact = strings.Join(words[1:], " ")

		case "hidden-service-dir":
			descriptor.HiddenServiceDir = true
		}
	}

	return descriptor.Fingerprint, func() *RouterDescriptor { return descriptor }, nil
}

// extractDescriptor extracts the first server descriptor from the given string
// blurb.  If successful, it returns the descriptor as a string and true or
// false, depending on if it extracted the last descriptor in the string blurb
// or not.
func extractDescriptor(blurb string) (string, bool, error) {

	start := strings.Index(blurb, "\nrouter ")
	if start == -1 {
		return "", false, fmt.Errorf("Cannot find beginning of descriptor: \"\\nrouter \"")
	}

	marker := "\n-----END SIGNATURE-----\n"
	end := strings.Index(blurb[start:], marker)
	if end == -1 {
		return "", false, fmt.Errorf("Cannot find end of descriptor: \"\\n-----END SIGNATURE-----\\n\"")
	}

	// Are we at the end?
	done := false
	if len(blurb) == (start + end + len(marker)) {
		done = true
	}

	return blurb[start : start+end+len(marker)], done, nil
}

// parseDescriptorFile parses the given file and returns a pointer to
// RouterDescriptors containing the router descriptors.  If there were any
// errors, an error string is returned.  If the lazy argument is set to true,
// parsing of the router descriptors is delayed until they are accessed.
func parseDescriptorFile(fileName string, lazy bool) (*RouterDescriptors, error) {

	var descriptors = NewRouterDescriptors()
	var descriptorParser func(descriptor string) (string, func() *RouterDescriptor, error)

	if lazy {
		descriptorParser = LazyParseRawDescriptor
	} else {
		descriptorParser = ParseRawDescriptor
	}

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	err = CheckAnnotation(fd, descriptorAnnotations)
	if err != nil {
		return nil, err
	}

	// We will read raw router descriptors from this channel.
	queue := make(chan QueueUnit)
	go DissectFile(fd, extractDescriptor, queue)

	// Parse incoming descriptors until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.Err != nil {
			return nil, unit.Err
		}

		fingerprint, getDescriptor, err := descriptorParser(unit.Blurb)
		if err != nil {
			return nil, err
		}

		descriptors.RouterDescriptors[strings.ToUpper(fingerprint)] = getDescriptor
	}

	return descriptors, nil
}

// LazilyParseDescriptorFile parses the given file and returns a pointer to
// RouterDescriptors containing the router descriptors.  If there were any
// errors, an error string is returned.  Note that parsing is done lazily which
// means that it is delayed until a given router descriptor is accessed.  That
// pays off when you know that you will not parse most router descriptors.
func LazilyParseDescriptorFile(fileName string) (*RouterDescriptors, error) {

	return parseDescriptorFile(fileName, true)
}

// ParseDescriptorFile parses the given file and returns a pointer to
// RouterDescriptors containing the router descriptors.  If there were any
// errors, an error string is returned.  Note that in contrast to
// LazilyParseDescriptorFile, parsing is *not* delayed.  That pays off when you
// know that you will parse most router descriptors.
func ParseDescriptorFile(fileName string) (*RouterDescriptors, error) {

	return parseDescriptorFile(fileName, false)
}
