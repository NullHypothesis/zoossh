// Provides generic operations for all supported data structures.

package zoossh

import (
	"fmt"
)

type ObjectCollector interface {
	PrintObjects()
}

// ParseUnknownFile attempts to parse a file whose content we don't know.  We
// try to use the right parser by looking at the file's annotation.  An
// ObjectCollector is returned if parsing was successful.
func ParseUnknownFile(fileName string) (ObjectCollector, error) {

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
