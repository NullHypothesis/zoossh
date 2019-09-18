// Provides generic operations for all supported data structures.

package zoossh

import (
	"fmt"
	"io"
	"net"
	"os"
)

// Fingerprint represents a relay's fingerprint as 40 hex digits.
type Fingerprint string

// Object defines functions that should be supported by a data element, e.g., a
// router descriptor, or a router status in a consensus.
type Object interface {
	String() string
	GetFingerprint() Fingerprint
}

// ObjectSet defines functions that should be supported by a set of objects.
type ObjectSet interface {
	Length() int
	Iterate(*ObjectFilter) <-chan Object
	GetObject(Fingerprint) (Object, bool)
	Merge(ObjectSet)
}

// ObjectFilter holds sets that consist of objects that should pass object set
// filtering.
type ObjectFilter struct {
	Fingerprints map[Fingerprint]struct{}
	IPAddrs      map[string]struct{}
	Nicknames    map[string]struct{}
}

// HasFingerprint returns true if the given fingerprint is present in the
// object filter.
func (filter *ObjectFilter) HasFingerprint(fpr Fingerprint) bool {
	_, exists := filter.Fingerprints[fpr]
	return exists
}

// HasIPAddr returns true if the given IP address is present in the object
// filter.
func (filter *ObjectFilter) HasIPAddr(addr net.IP) bool {
	_, exists := filter.IPAddrs[addr.String()]
	return exists
}

// HasNickname returns true if the given nickname is present in the object
// filter.
func (filter *ObjectFilter) HasNickname(nickname string) bool {
	_, exists := filter.Nicknames[nickname]
	return exists
}

// AddFingerprint adds the given fingerprint to the object filter.
func (filter *ObjectFilter) AddFingerprint(fpr Fingerprint) {
	filter.Fingerprints[fpr] = struct{}{}
}

// AddIPAddr adds the given IP address to the object filter.
func (filter *ObjectFilter) AddIPAddr(addr net.IP) {
	filter.IPAddrs[addr.String()] = struct{}{}
}

// AddNickname adds the given nickname to the object filter.
func (filter *ObjectFilter) AddNickname(nickname string) {
	filter.Nicknames[nickname] = struct{}{}
}

// IsEmpty returns true if the object filter is empty.
func (filter *ObjectFilter) IsEmpty() bool {

	return len(filter.Fingerprints) == 0 &&
		len(filter.IPAddrs) == 0 &&
		len(filter.Nicknames) == 0
}

// NewObjectFilter returns a newly allocated object filter instance.
func NewObjectFilter() *ObjectFilter {

	return &ObjectFilter{
		make(map[Fingerprint]struct{}),
		make(map[string]struct{}),
		make(map[string]struct{}),
	}
}

// parseWithAnnotation parses the input using a parser appropriate for the given
// annotation.  The input should not have an annotation of its own (it should
// already have been read).  Returns an error if the annotation is of an unknown
// type.  Otherwise, returns the output of the chosen parser.
func parseWithAnnotation(r io.Reader, annotation *Annotation) (ObjectSet, error) {

	// Use the annotation to find the right parser.
	if _, ok := descriptorAnnotations[*annotation]; ok {
		return parseDescriptorUnchecked(r, false)
	}

	if _, ok := consensusAnnotations[*annotation]; ok {
		return parseConsensusUnchecked(r, false)
	}

	return nil, fmt.Errorf("could not find suitable parser")
}

// ParseUnknown first reads a type annotation and passes it along with the rest
// of the input to parseWithAnnotation.
func ParseUnknown(r io.Reader) (ObjectSet, error) {

	annotation, r, err := readAnnotation(r)
	if err != nil {
		return nil, err
	}

	return parseWithAnnotation(r, annotation)
}

// ParseUnknownFile attempts to parse a file whose content we don't know.  We
// try to use the right parser by looking at the file's annotation.  An
// ObjectSet is returned if parsing was successful.
func ParseUnknownFile(fileName string) (ObjectSet, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return ParseUnknown(fd)
}
