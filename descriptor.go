// Parses files containing server descriptors.

package zoossh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// The layout of the "published" field.
	publishedTimeLayout = "2006-01-02 15:04:05"
)

var descriptorAnnotations = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"server-descriptor", "1", "0"}: true,
}

type GetDescriptor func() *RouterDescriptor

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
	Fingerprint Fingerprint

	// The single fields of a "hibernating" line.
	Hibernating bool

	// The single fields of a "family" line.
	Family map[Fingerprint]bool

	// The single fields of a "contact" line.
	Contact string

	// The "hidden-service-dir" line.
	HiddenServiceDir bool

	OnionKey     string
	NTorOnionKey string
	SigningKey   string

	RawAccept     string
	RawReject     string
	RawExitPolicy string

	Accept []*ExitPattern
	Reject []*ExitPattern
}

type RouterDescriptors struct {

	// A map from relay fingerprint to a function which returns the router
	// descriptor.
	RouterDescriptors map[Fingerprint]GetDescriptor
}

// String implements the String as well as the Object interface.  It returns
// the descriptor's string representation.
func (desc *RouterDescriptor) String() string {

	return fmt.Sprintf("%s,%s,%s,%d,%d,%s,%d,%s,%s,%s",
		desc.Fingerprint,
		desc.Nickname,
		desc.Address,
		desc.ORPort,
		desc.DirPort,
		desc.Published.Format(time.RFC3339),
		desc.Uptime,
		strings.Replace(desc.OperatingSystem, ",", "", -1),
		strings.Replace(desc.TorVersion, ",", "", -1),
		strings.Replace(desc.Contact, ",", "", -1))
}

// GetFingerprint implements the Object interface.  It returns the descriptor's
// fingerprint.
func (desc *RouterDescriptor) GetFingerprint() Fingerprint {

	return desc.Fingerprint
}

// Length implements the ObjectSet interface.  It returns the length of the
// router descriptors.
func (descs *RouterDescriptors) Length() int {

	return len(descs.RouterDescriptors)
}

// Iterate implements the ObjectSet interface.  Using a channel, it iterates
// over and returns all router descriptors.  The given object filter can be
// used to filter descriptors, e.g., by fingerprint.
func (descs *RouterDescriptors) Iterate(filter *ObjectFilter) <-chan Object {

	ch := make(chan Object)

	go func() {
		for _, getDesc := range descs.RouterDescriptors {
			desc := getDesc()
			if filter == nil || filter.IsEmpty() || filter.MatchesRouterDescriptor(desc) {
				ch <- desc
			}
		}
		close(ch)
	}()

	return ch
}

// GetObject implements the ObjectSet interface.  It returns the object
// identified by the given fingerprint.  If the object is not present in the
// set, false is returned, otherwise true.
func (desc *RouterDescriptors) GetObject(fingerprint Fingerprint) (Object, bool) {

	return desc.Get(fingerprint)
}

// Merge merges the given object set with itself.
func (descs *RouterDescriptors) Merge(objs ObjectSet) {

	for desc := range descs.Iterate(nil) {
		fpr := desc.GetFingerprint()
		_, exists := descs.Get(fpr)
		if !exists {
			descs.Set(fpr, desc.(*RouterDescriptor))
		}
	}
}

// NewRouterDescriptors serves as a constructor and returns a pointer to a
// freshly allocated and empty RouterDescriptors struct.
func NewRouterDescriptors() *RouterDescriptors {

	return &RouterDescriptors{RouterDescriptors: make(map[Fingerprint]GetDescriptor)}
}

// NewRouterDescriptor serves as a constructor and returns a pointer to a
// freshly allocated and empty RouterDescriptor struct.
func NewRouterDescriptor() *RouterDescriptor {

	return &RouterDescriptor{Family: make(map[Fingerprint]bool)}
}

// ToSlice converts the given router descriptors to a slice.
func (rd *RouterDescriptors) ToSlice() []GetDescriptor {

	length := rd.Length()
	descs := make([]GetDescriptor, length)

	i := 0
	for _, getDesc := range rd.RouterDescriptors {
		descs[i] = getDesc
		i += 1
	}

	return descs
}

// Get returns the router descriptor for the given fingerprint and a boolean
// value indicating if the descriptor could be found.
func (d *RouterDescriptors) Get(fingerprint Fingerprint) (*RouterDescriptor, bool) {

	getDescriptor, exists := d.RouterDescriptors[SanitiseFingerprint(fingerprint)]
	if !exists {
		return nil, exists
	}

	return getDescriptor(), exists
}

// Set adds a new fingerprint mapping to a function returning the router
// descriptor.
func (d *RouterDescriptors) Set(fingerprint Fingerprint, descriptor *RouterDescriptor) {

	d.RouterDescriptors[SanitiseFingerprint(fingerprint)] = func() *RouterDescriptor {
		return descriptor
	}
}

// HasFamily returns true if the given relay identified by its fingerprint is
// part of this relay's family.
func (desc *RouterDescriptor) HasFamily(fingerprint Fingerprint) bool {

	_, ok := desc.Family[SanitiseFingerprint(fingerprint)]
	return ok
}

// LazyParseRawDescriptor lazily parses a raw router descriptor (in string
// format) and returns the descriptor's fingerprint, a function returning the
// descriptor, and an error if the descriptor could not be parsed.  Parsing is
// delayed until the router descriptor is accessed.
func LazyParseRawDescriptor(rawDescriptor string) (Fingerprint, GetDescriptor, error) {

	var fingerprint Fingerprint

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
			fingerprint = Fingerprint(strings.Join(words[1:], ""))
			return SanitiseFingerprint(fingerprint), getDescriptor, nil
		}
	}

	return "", nil, fmt.Errorf("could not extract descriptor fingerprint")
}

// ParseRawDescriptor parses a raw router descriptor (in string format) and
// returns the descriptor's fingerprint, a function returning the descriptor,
// and an error if the descriptor could not be parsed.  In contrast to
// LazyParseRawDescriptor, parsing is *not* delayed.
func ParseRawDescriptor(rawDescriptor string) (Fingerprint, GetDescriptor, error) {

	var descriptor *RouterDescriptor = NewRouterDescriptor()

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
			for i := 0; i < len(words); i++ {
				if (strings.TrimSpace(words[i]) == "on") && (i < len(words)-1) {
					descriptor.OperatingSystem = strings.Join(words[i+1:], " ")
					descriptor.TorVersion = strings.Join(words[1:i-1], " ")
					break
				}
			}

		case "uptime":
			descriptor.Uptime, _ = strconv.ParseUint(words[1], 10, 64)

		case "published":
			time, _ := time.Parse(publishedTimeLayout, strings.Join(words[1:], " "))
			descriptor.Published = time

		case "fingerprint":
			descriptor.Fingerprint = SanitiseFingerprint(Fingerprint(strings.Join(words[1:], "")))

		case "hibernating":
			descriptor.Hibernating, _ = strconv.ParseBool(words[1])

		case "bandwidth":
			descriptor.BandwidthAvg, _ = strconv.ParseUint(words[1], 10, 64)
			descriptor.BandwidthBurst, _ = strconv.ParseUint(words[2], 10, 64)
			descriptor.BandwidthObs, _ = strconv.ParseUint(words[3], 10, 64)

		case "family":
			for _, word := range words[1:] {
				fpr := Fingerprint(strings.Trim(word, "$"))
				descriptor.Family[fpr] = true
			}

		case "contact":
			descriptor.Contact = strings.Join(words[1:], " ")

		case "hidden-service-dir":
			descriptor.HiddenServiceDir = true

		case "reject":
			descriptor.RawReject += words[1] + " "
			descriptor.RawExitPolicy += words[0] + " " + words[1] + "\n"

		case "accept":
			descriptor.RawAccept += words[1] + " "
			descriptor.RawExitPolicy += words[0] + " " + words[1] + "\n"
		}
	}

	return descriptor.Fingerprint, func() *RouterDescriptor { return descriptor }, nil
}

// extractDescriptor is a bufio.SplitFunc that extracts individual router
// descriptors.
func extractDescriptor(data []byte, atEOF bool) (advance int, token []byte, err error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	start := 0
	if !bytes.HasPrefix(data, []byte("router ")) {
		start = bytes.Index(data, []byte("\nrouter "))
		if start < 0 {
			if atEOF {
				return 0, nil, fmt.Errorf("cannot find beginning of descriptor: \"\\nrouter \"")
			}
			// Request more data.
			return 0, nil, nil
		}
		start++
	}

	marker := []byte("\n-----END SIGNATURE-----\n")
	end := bytes.Index(data[start:], marker)
	if end >= 0 {
		return start + end + len(marker), data[start : start+end+len(marker)], nil
	}
	if atEOF {
		return start, nil, fmt.Errorf("cannot find end of descriptor: %q", marker)
	}
	// Request more data.
	return start, nil, nil
}

// MatchesRouterDescriptor returns true if fields of the given router
// descriptor are present in the object filter, e.g., the descriptor's nickname
// is part of the object filter.
func (filter *ObjectFilter) MatchesRouterDescriptor(desc *RouterDescriptor) bool {

	if filter.HasIPAddr(desc.Address) {
		return true
	}

	if filter.HasFingerprint(desc.Fingerprint) {
		return true
	}

	if filter.HasNickname(desc.Nickname) {
		return true
	}

	return false
}

// parseDescriptorUnchecked parses a descriptor of type "server-descriptor".
// The input should be without a type annotation; i.e., the type annotation
// should already have been read and checked to be the correct type.  The
// function returns a pointer to RouterDescriptors containing the router
// descriptors.  If there were any errors, an error string is returned.  If the
// lazy argument is set to true, parsing of the router descriptors is delayed
// until they are accessed.
func parseDescriptorUnchecked(r io.Reader, lazy bool) (*RouterDescriptors, error) {

	var descriptors = NewRouterDescriptors()
	var descriptorParser func(descriptor string) (Fingerprint, GetDescriptor, error)

	if lazy {
		descriptorParser = LazyParseRawDescriptor
	} else {
		descriptorParser = ParseRawDescriptor
	}

	// We will read raw router descriptors from this channel.
	queue := make(chan QueueUnit)
	go DissectFile(r, extractDescriptor, queue)

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

		descriptors.RouterDescriptors[SanitiseFingerprint(fingerprint)] = getDescriptor
	}

	return descriptors, nil
}

// parseDescriptor is a wrapper around parseDescriptorUnchecked that first reads
// and checks the type annotation to make sure it belongs to
// descriptorAnnotations.
func parseDescriptor(r io.Reader, lazy bool) (*RouterDescriptors, error) {

	r, err := readAndCheckAnnotation(r, descriptorAnnotations)
	if err != nil {
		return nil, err
	}

	return parseDescriptorUnchecked(r, lazy)
}

// parseDescriptorFile is a wrapper around parseDescriptor that opens the named
// file for parsing.
func parseDescriptorFile(fileName string, lazy bool) (*RouterDescriptors, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return parseDescriptor(fd, lazy)
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
