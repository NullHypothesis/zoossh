package zoossh

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

var bridgeNetworkStatusAnnotations = map[Annotation]bool{
	// The file format we currently (try to) support.
	Annotation{"bridge-network-status", "1", "2"}: true,
}

type BridgeNetworkStatus struct {
	RouterStatuses map[Fingerprint]GetStatus
}

// Iterate implements the ObjectSet interface.  Using a channel, it iterates
// over and returns all router statuses.  The given object filter can be used
// to filter router statuses, e.g., by fingerprint.
func (bn *BridgeNetworkStatus) Iterate(filter *ObjectFilter) <-chan Object {

	ch := make(chan Object)

	go func() {
		for _, getStatus := range bn.RouterStatuses {
			status := getStatus()
			if filter == nil || filter.IsEmpty() || filter.MatchesRouterStatus(status) {
				ch <- status
			}
		}
		close(ch)
	}()

	return ch
}

// parseBridgeStatusUnchecked parses a descriptor of type
// "bridge-network-status".  The input should be without a type annotation;
// i.e., the type annotation should already have been read and checked to be the
// correct type.  The function returns a network consensus if parsing was
// successful.  If there were any errors, an error string is returned.  If the
// lazy argument is set to true, parsing of the router statuses is delayed until
// they are accessed.
func parseBridgeStatusUnchecked(r io.Reader, lazy bool) (*BridgeNetworkStatus, error) {

	var networkstatus = BridgeNetworkStatus{RouterStatuses: make(map[Fingerprint]GetStatus)}
	var statusParser func(string) (Fingerprint, GetStatus, error)

	if lazy {
		statusParser = LazyParseRawStatus
	} else {
		statusParser = ParseRawStatus
	}

	// We will read raw router statuses from this channel.
	queue := make(chan QueueUnit)
	go DissectFile(r, extractBridgeStatusEntry, queue)

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

		networkstatus.RouterStatuses[SanitiseFingerprint(fingerprint)] = getStatus
	}

	return &networkstatus, nil
}

// extractBridgeStatusEntry is a bufio.SplitFunc that extracts individual network
// status entries.
func extractBridgeStatusEntry(data []byte, atEOF bool) (advance int, token []byte, err error) {

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
		return len(data), data[start:], nil
	}
	// Request more data.
	return 0, nil, nil
}

// parseBridgeStatus is a wrapper around parseBridgeStatusUnchecked that first reads
// and checks the type annotation to make sure it belongs to
// bridgeNetworkStatusAnnotations.
func parseBridgeStatus(r io.Reader, lazy bool) (*BridgeNetworkStatus, error) {

	r, err := readAndCheckAnnotation(r, bridgeNetworkStatusAnnotations)
	if err != nil {
		return nil, err
	}

	return parseBridgeStatusUnchecked(r, lazy)
}

// parseBridgeStatusFile is a wrapper around parseConsensus that opens the named
// file for parsing.
func parseBridgeStatusFile(fileName string, lazy bool) (*BridgeNetworkStatus, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return parseBridgeStatus(fd, lazy)
}

// parseBridgeStatusFileUnchecked is a wrapper around parseNetworkstatusUnchecked that opens the named
// file for parsing.
func parseBridgeStatusFileUnchecked(fileName string, lazy bool) (*BridgeNetworkStatus, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	return parseBridgeStatusUnchecked(fd, lazy)
}

// ParseRawBridgeStatus parses a raw consensus (in string format) and
// returns a network consensus if parsing was successful.
func ParseRawBridgeStatus(rawBridgeStatus string, lazy bool) (*BridgeNetworkStatus, error) {
	r := strings.NewReader(rawBridgeStatus)

	return parseBridgeStatus(r, lazy)
}

// LazilyParseBridgeStatusFile parses the given file and returns a network
// consensus if parsing was successful.  If there were any errors, an error
// string is returned.  Parsing of the router statuses is delayed until they
// are accessed using the Get method.  As a result, this function is
// recommended as long as you won't access more than ~50% of all statuses.
func LazilyParseBridgeStatusFile(fileName string) (*BridgeNetworkStatus, error) {

	return parseBridgeStatusFile(fileName, true)
}

// ParseBridgeStatusFile parses the given file and returns a network consensus if
// parsing was successful.  If there were any errors, an error string is
// returned.  In contrast to LazilyParseBridgeStatusFile, parsing of router
// statuses is *not* delayed.  As a result, this function is recommended as
// long as you will access most of all statuses.
func ParseBridgeStatusFile(fileName string) (*BridgeNetworkStatus, error) {

	return parseBridgeStatusFile(fileName, false)
}

// ParseRawUnsafeBridgeStatus parses a raw consensus (in string format) and
// returns a network consensus if parsing was successful.
func ParseRawUnsafeBridgeStatus(rawBridgeStatus string, lazy bool) (*BridgeNetworkStatus, error) {
	r := strings.NewReader(rawBridgeStatus)

	return parseBridgeStatusUnchecked(r, lazy)
}

// LazilyParseUnsafeBridgeStatusFile parses the given file without checking the
// annotations and returns a network consensus if parsing was successful. If
// there were any errors, consensus if parsing was successful.  If there were
// any errors, an error string is returned.  Parsing of the router statuses is
// delayed until they are accessed using the Get method.  As a result, this
// function is recommended as long as you won't access more than ~50% of all
// statuses.
func LazilyParseUnsafeBridgeStatusFile(fileName string) (*BridgeNetworkStatus, error) {

	return parseBridgeStatusFileUnchecked(fileName, true)
}

// ParseUnsafeBridgeStatusFile parses the given file without checking the annotations
// and returns a network consensus if parsing was successful. If there were any
// errors, an error string is returned.  In contrast to LazilyParseBridgeStatusFile,
// parsing of router statuses is *not* delayed.  As a result, this function is
// recommended as long as you will access most of all statuses.
func ParseUnsafeBridgeStatusFile(fileName string) (*BridgeNetworkStatus, error) {

	return parseBridgeStatusFileUnchecked(fileName, false)
}
