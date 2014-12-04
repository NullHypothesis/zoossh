// Provides utility functions.

package zoossh

import (
	"io/ioutil"
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

func ParseFile(fileName string, delim Delimiter, queue chan QueueUnit) {

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
