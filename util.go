// Provides utility functions.

package zoossh

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type QueueUnit struct {
	Blurb string
	Err   error
}

type Annotation struct {
	Type  string
	Major string
	Minor string
}

// Extracts a string unit from an archive file that can be readily thrown into
// the respective parser.
type StringExtractor func(string) (string, bool, error)

// DescCache maps a descriptor's digest to its router descriptor.
var DescCache = make(map[string]*RouterDescriptor)

func (a *Annotation) String() string {

	return fmt.Sprintf("@type %s %s.%s", a.Type, a.Major, a.Minor)
}

// Equals checks whether the two given annotations have the same content.
func (a *Annotation) Equals(b *Annotation) bool {

	return (*a).Type == (*b).Type && (*a).Major == (*b).Major && (*a).Minor == (*b).Minor
}

// This is the same regexp Stem uses.
// https://gitweb.torproject.org/stem.git/tree/stem/descriptor/__init__.py?id=1.4.1#n182
var annotationRegexp = regexp.MustCompile(`^@type (\S+) (\d+)\.(\d+)$`)

// parseAnnotation parses a type annotation string in the form
// "@type $descriptortype $major.$minor".
func parseAnnotation(annotationText string) (*Annotation, error) {

	matches := annotationRegexp.FindStringSubmatch(annotationText)
	if matches == nil {
		return nil, fmt.Errorf("bad syntax: %q", annotationText)
	}

	annotation := new(Annotation)
	annotation.Type = matches[1]
	annotation.Major = matches[2]
	annotation.Minor = matches[3]

	return annotation, nil
}

// Decodes the given Base64-encoded string and returns the resulting string.
// If there are errors during decoding, an error string is returned.
func Base64ToString(encoded string) (string, error) {

	// dir-spec.txt says that Base64 padding is removed so we have to account
	// for that here.
	if rem := len(encoded) % 4; rem != 0 {
		encoded += strings.Repeat("=", 4-rem)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(decoded), nil
}

// readAnnotation reads and parses the first line of the the io.Reader, then
// returns the resulting *Annotation as well as a new io.Reader ready to read
// the rest of the file.
func readAnnotation(r io.Reader) (*Annotation, io.Reader, error) {

	br := bufio.NewReader(r)

	// The annotation is placed in the first line of the file.  See the
	// following URL for details:
	// <https://collector.torproject.org/formats.html>
	// Use ReadSlice rather than ReadBytes in order to get ErrBufferFull
	// when there is no '\n' byte.
	slice, err := br.ReadSlice('\n')
	if err != nil {
		return nil, nil, err
	}

	// Trim the trailing '\n'.
	line := string(slice[:len(slice)-1])
	annotation, err := parseAnnotation(line)
	if err != nil {
		return nil, nil, err
	}

	return annotation, br, nil
}

// Checks the type annotation in the given io.Reader.  The Annotation struct
// determines what we want to see.  If we don't see the expected annotation, an
// error string is returned.
func readAndCheckAnnotation(r io.Reader, expected map[Annotation]bool) (io.Reader, error) {

	observed, r, err := readAnnotation(r)
	if err != nil {
		return nil, err
	}

	for annotation, _ := range expected {
		// We support the observed annotation.
		if annotation.Equals(observed) {
			return r, nil
		}
	}

	return nil, fmt.Errorf("Unexpected file annotation: %s", observed)
}

// GetAnnotation obtains and returns the given file's annotation.  If anything
// fails in the process, an error string is returned.
func GetAnnotation(fileName string) (*Annotation, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	annotation, _, err := readAnnotation(fd)
	if err != nil {
		return nil, fmt.Errorf("Could not read file annotation for \"%s\": %s", fileName, err)
	}

	return annotation, nil
}

// Checks the type annotation in the given file.  The Annotation struct
// determines what we want to see in the file.  If we don't see the expected
// annotation, an error string is returned.
func CheckAnnotation(fd *os.File, expected map[Annotation]bool) error {

	before, err := fd.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}

	// The annotation is placed in the first line of the file.  See the
	// following URL for details:
	// <https://metrics.torproject.org/collector.html#data-formats>
	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	annotation := scanner.Text()

	// Set file descriptor back because NewScanner() reads and buffers large
	// chunks of data.
	fd.Seek(before+int64(len(annotation)), os.SEEK_SET)

	observed, err := parseAnnotation(annotation)
	if err != nil {
		return err
	}

	for annotation, _ := range expected {
		// We support the observed annotation.
		if annotation.Equals(observed) {
			return nil
		}
	}

	return fmt.Errorf("Unexpected file annotation: %q", annotation)
}

// Dissects the given file into string chunks by using the given string
// extraction function.  The resulting string chunks are then written to the
// given queue where the receiving end parses them.
func DissectFile(r io.Reader, extractor bufio.SplitFunc, queue chan QueueUnit) {

	defer close(queue)

	scanner := bufio.NewScanner(r)
	scanner.Split(extractor)

	for scanner.Scan() {
		unit := scanner.Text()
		queue <- QueueUnit{unit, nil}
	}

	if err := scanner.Err(); err != nil {
		queue <- QueueUnit{"", err}
	}
}

// Convert the given port string to an unsigned 16-bit integer.  If the
// conversion fails or the number cannot be represented in 16 bits, 0 is
// returned.
func StringToPort(portStr string) uint16 {

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return uint16(0)
	}

	return uint16(portNum)
}

// SanitiseFingerprint returns a sanitised version of the given fingerprint by
// making it upper case and removing leading and trailing white spaces.
func SanitiseFingerprint(fingerprint Fingerprint) Fingerprint {

	sanitised := strings.ToUpper(strings.TrimSpace(string(fingerprint)))

	return Fingerprint(sanitised)
}

// LoadDescriptorFromDigest takes as input the descriptor directory, a
// descriptor's digest, and the date the digest was created.  It then attempts
// to parse and return the descriptor referenced by the digest.  The descriptor
// directory expects to contain CollecTor server descriptor archives such as:
// server-descriptors-2015-03/
// server-descriptors-2015-04/
// ...
func LoadDescriptorFromDigest(descriptorDir, digest string, date time.Time) (*RouterDescriptor, error) {

	// Check if we already have the descriptor in our local cache.
	if desc, exists := DescCache[digest]; exists {
		return desc, nil
	}

	topDir := fmt.Sprintf("server-descriptors-%s", date.Format("2006-01"))
	prevTopDir := fmt.Sprintf("server-descriptors-%s", date.AddDate(0, -1, 0).Format("2006-01"))
	fileName := filepath.Join(descriptorDir, topDir, digest[0:1], digest[1:2], digest)

	// If we cannot find the descriptor file, go one month back in time.
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		fileName = filepath.Join(descriptorDir, prevTopDir, digest[0:1], digest[1:2], digest)
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			return nil, fmt.Errorf("Could not find digest file %s in %s", digest, descriptorDir)
		}
	}

	descs, err := ParseDescriptorFile(fileName)
	if err != nil {
		return nil, err
	}

	if descs.Length() != 1 {
		return nil, fmt.Errorf("More than one descriptor in digest file %s.  Bug?", fileName)
	}

	var d *RouterDescriptor
	for _, getDesc := range descs.RouterDescriptors {
		d = getDesc()
		break
	}
	DescCache[digest] = d
	return d, nil
}
