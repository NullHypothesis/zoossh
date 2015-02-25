// Tests functions from "generic.go".

package zoossh

import (
	"os"
	"testing"
)

// Test the function ParseUnknownFile().
func TestParseUnknownFile(t *testing.T) {

	_, err := ParseUnknownFile("/dev/zero")
	if err == nil {
		t.Errorf("ParseUnknownFile() failed to reject /dev/zero.")
	}

	// Only run this test if the consensus file is there.
	if _, err = os.Stat(consensusFile); err == nil {
		_, err := ParseUnknownFile(consensusFile)
		if err != nil {
			t.Errorf("ParseUnknownFile() failed to parse %s.", consensusFile)
		}
	}
}
