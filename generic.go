// Provides generic operations for all supported data structures.

package zoossh

import (
	"fmt"
)

// Object defines functions that should be supported by a data element, e.g., a
// router descriptor, or a router status in a consensus.
type Object interface {
	String() string
	GetFingerprint() string
}

// ObjectSet defines functions that should be supported by a set of objects.
type ObjectSet interface {
	Length() int
	Iterate() <-chan Object
	GetObject(string) (Object, bool)
	Merge(ObjectSet)
}

// ParseUnknownFile attempts to parse a file whose content we don't know.  We
// try to use the right parser by looking at the file's annotation.  An
// ObjectSet is returned if parsing was successful.
func ParseUnknownFile(fileName string) (ObjectSet, error) {

	// First, get the file's annotation which we then use to figure out what
	// parser we need.
	annotation, err := GetAnnotation(fileName)
	if err != nil {
		return nil, err
	}

	// Now use the annotation to find the right parser.
	if _, ok := descriptorAnnotations[*annotation]; ok {
		return ParseDescriptorFile(fileName)
	}

	if _, ok := consensusAnnotations[*annotation]; ok {
		return ParseConsensusFile(fileName)
	}

	return nil, fmt.Errorf("Could not find suitable parser for file %s.", fileName)
}
