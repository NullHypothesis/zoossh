// Tests functions from "util.go".

package zoossh

import (
	"os"
	"testing"
)

// Run the file "setup_tests.sh" in the scripts/ directory to obtain these
// files.
const (
	serverDescriptorFile = "/tmp/server-descriptors"
	consensusFile        = "/tmp/consensus"
)

// Test the function Base64ToString().
func TestBase64ToString(t *testing.T) {

	// Use a typical Base64-encoded 20-byte fingerprint.
	dec, err := Base64ToString("OVSyFvUCAKNSYpz8ZPArMLqf0Ds=")
	if err != nil {
		t.Error("Failed to decode Base64.")
	}

	if dec != "3954b216f50200a352629cfc64f02b30ba9fd03b" {
		t.Error("Base64 chunk decoded incorrectly.")
	}

	dec, err = Base64ToString("OVSyFvUCAKNSYpz8ZPArMLqf0Ds")
	if err != nil {
		t.Error("Failed to decode Base64 (with missing padding).")
	}

	if dec != "3954b216f50200a352629cfc64f02b30ba9fd03b" {
		t.Error("Base64 chunk decoded incorrectly.")
	}
}

// Test the function StringToPort().
func TestStringToPort(t *testing.T) {

	port := StringToPort("65536")
	if port != 0 {
		t.Error("Bad return value for invalid port.")
	}

	port = StringToPort("65535")
	if port != 65535 {
		t.Error("Bad return value for valid port.")
	}

	port = StringToPort("foobar")
	if port != 0 {
		t.Error("Bad return value for invalid input.")
	}
}

// Test the function CheckAnnotation().
func TestCheckAnnotation(t *testing.T) {

	var err error

	goodSDAnnotation := &Annotation{
		supportedDescriptorType,
		supportedDescriptorMajor,
		supportedDescriptorMinor}

	goodCAnnotation := &Annotation{
		supportedStatusType,
		supportedStatusMajor,
		supportedStatusMinor}

	err = CheckAnnotation("/foo/bar/foo/bar", goodSDAnnotation)
	if err == nil {
		// Seriously?
		t.Error("CheckAnnotation() failed to reject crazy file.")
	}

	// Only run this test if the descriptors file is there.
	if _, err = os.Stat(serverDescriptorFile); err == nil {

		err = CheckAnnotation(serverDescriptorFile, goodSDAnnotation)
		if err != nil {
			t.Error("CheckAnnotation() failed to accept annotation: ", err)
		}

		err = CheckAnnotation(serverDescriptorFile, goodCAnnotation)
		if err == nil {
			t.Error("CheckAnnotation() failed to reject annotation.")
		}
	}

	// Only run this test if the consensus file is there.
	if _, err = os.Stat(consensusFile); err == nil {

		err = CheckAnnotation(consensusFile, goodCAnnotation)
		if err != nil {
			t.Error("CheckAnnotation() failed to accept annotation: ", err)
		}

		err = CheckAnnotation(consensusFile, goodSDAnnotation)
		if err == nil {
			t.Error("CheckAnnotation() failed to reject annotation.")
		}
	}
}