// Provides utility functions.

package zoossh

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
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

// GetAnnotation obtains and returns the given file's annotation.  If anything
// fails in the process, an error string is returned.
func GetAnnotation(fileName string) (*Annotation, error) {

	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	// Fetch the file's first line which should be the annotation.

	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	annotationText := scanner.Text()

	annotation := new(Annotation)

	// We expect "@type TYPE VERSION".
	words := strings.Split(annotationText, " ")
	if len(words) != 3 {
		return nil, fmt.Errorf("Could not parse file annotation for \"%s\".", fileName)
	}
	annotation.Type = words[1]

	// We expect "MAJOR.MINOR".
	version := strings.Split(words[2], ".")
	if len(version) != 2 {
		return nil, fmt.Errorf("Could not parse file annotation for \"%s\".", fileName)
	}
	annotation.Major = version[0]
	annotation.Minor = version[1]

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
	// <https://collector.torproject.org/formats.html>
	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	annotation := scanner.Text()

	// Set file descriptor back because NewScanner() reads and buffers large
	// chunks of data.
	fd.Seek(before+int64(len(annotation)), os.SEEK_SET)

	invalidFormat := fmt.Errorf("Unexpected file annotation: %s", annotation)

	// We expect "@type TYPE VERSION".
	words := strings.Split(annotation, " ")
	if len(words) != 3 {
		return invalidFormat
	}

	// We expect "MAJOR.MINOR".
	version := strings.Split(words[2], ".")
	if len(version) != 2 {
		return invalidFormat
	}
	observed := Annotation{words[1], version[0], version[1]}

	for annotation, _ := range expected {
		// We support the observed annotation.
		if annotation.Equals(&observed) {
			return nil
		}
	}

	return invalidFormat
}

// Dissects the given file into string chunks by using the given string
// extraction function.  The resulting string chunks are then written to the
// given queue where the receiving end parses them.
func DissectFile(fd *os.File, extractor StringExtractor, queue chan QueueUnit) {

	defer close(queue)

	blurb, err := ioutil.ReadAll(fd)
	if err != nil {
		queue <- QueueUnit{"", err}
	}

	rawContent := string(blurb)

	for {
		unit, done, err := extractor(rawContent)
		if err != nil {
			log.Println("Error in extraction function: ", err)
			break
		}

		queue <- QueueUnit{unit, nil}
		rawContent = rawContent[len(unit):]

		if done {
			break
		}
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
