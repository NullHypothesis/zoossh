// Provides utility functions.

package zoossh

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

type QueueUnit struct {
	Blurb string
	Err   error
}

type Delimiter struct {
	Pattern string
	Offset  uint
}

type Annotation struct {
	Type  string
	Major string
	Minor string
}

func (a *Annotation) String() string {

	return fmt.Sprintf("@type %s %s.%s", a.Type, a.Major, a.Minor)
}

// Checks the type annotation in the given file.  The Annotation struct
// determines what we want to see in the file.  If we don't see the expected
// annotation, an error string is returned.
func CheckAnnotation(fileName string, expected *Annotation) error {

	fd, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer fd.Close()

	// The annotation is placed in the first line of the file.  See the
	// following URL for details:
	// <https://collector.torproject.org/formats.html>
	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	annotation := scanner.Text()

	invalidFormat := fmt.Errorf("Invalid format for file annotation.  "+
		"Expected \"%s\" but got \"%s\".", expected, annotation)

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

	// Check annotation type.
	if (words[0] != "@type") || (words[1] != expected.Type) {
		return fmt.Errorf("Invalid annotation type.  Expected \"@type %s\" "+
			"but got \"%s %s\".", expected.Type, words[0], words[1])
	}

	// Check major and minor version number.
	if (version[0] != expected.Major) || (version[1] != expected.Minor) {
		return fmt.Errorf("Invalid annotation version.  Expected \"%s.%s\" "+
			"but got \"%s.%s\".", expected.Major, expected.Minor, version[0],
			version[1])
	}

	return nil
}

// Dissects the given file into string chunks as specified by the given
// delimiter.  The resulting string chunks are then written to the given queue
// where the receiving end parses them.
func DissectFile(fileName string, delim Delimiter, queue chan QueueUnit) {

	defer close(queue)

	blurb, err := ioutil.ReadFile(fileName)
	if err != nil {
		queue <- QueueUnit{"", err}
	}

	rawContent := string(blurb)

	for {
		// Jump to the end of the next string blurb.
		position := strings.Index(rawContent, delim.Pattern)
		if position == -1 {
			break
		}
		position += int(delim.Offset)

		queue <- QueueUnit{rawContent[:position], nil}

		// Point to the beginning of the next string blurb.
		rawContent = rawContent[position:]
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
