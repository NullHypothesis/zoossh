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

// Test the function String().
func TestAnnotationString(t *testing.T) {

	a := Annotation{"foobar", "0", "0"}
	s := a.String()

	if s != "@type foobar 0.0" {
		t.Errorf("Badly formatted annotation: %s", s)
	}
}

// Test the function Equals().
func TestAnnotationEquals(t *testing.T) {

	a := Annotation{"a", "b", "c"}
	b := Annotation{"a", "b", "c"}
	z := Annotation{"x", "y", "z"}

	if !a.Equals(&b) || !b.Equals(&a) {
		t.Error("Equals() incorrectly classified annotations as unequal.")
	}

	if a.Equals(&z) || z.Equals(&a) || b.Equals(&z) || z.Equals(&b) {
		t.Error("Equals() incorrectly classified annotations as equal.")
	}
}

// Test the function GetAnnotation().
func TestGetAnnotation(t *testing.T) {

	expectedDescriptorAnnotation := &Annotation{"server-descriptor", "1", "0"}
	expectedConsensusAnnotation := &Annotation{"network-status-consensus-3", "1", "0"}

	// Parse our provided server descriptor file which should work.
	if _, err := os.Stat(serverDescriptorFile); err == nil {
		annotation, err := GetAnnotation(serverDescriptorFile)
		if err != nil {
			t.Errorf("GetAnnotation() failed to fetch annotation from \"%s\".", serverDescriptorFile)
		}

		if !annotation.Equals(expectedDescriptorAnnotation) {
			t.Errorf("Extracted annotation not as expected in \"%s\".", serverDescriptorFile)
		}
	}

	// Parse our provided consensus file which should work.
	if _, err := os.Stat(consensusFile); err == nil {
		annotation, err := GetAnnotation(consensusFile)
		if err != nil {
			t.Errorf("GetAnnotation() failed to fetch annotation from \"%s\".", consensusFile)
		}

		if !annotation.Equals(expectedConsensusAnnotation) {
			t.Errorf("Extracted annotation not as expected in \"%s\".", consensusFile)
		}
	}

	// Make sure that a bogus file raises an error.
	_, err := GetAnnotation("/dev/zero")
	if err == nil {
		t.Error("GetAnnotation() failed to raise an error for /dev/zero.")
	}
}

// Test the function CheckAnnotation().
func TestCheckAnnotation(t *testing.T) {

	var err error

	fd, err := os.Open("/dev/zero")
	if err == nil {
		err = CheckAnnotation(fd, descriptorAnnotations)
		if err == nil {
			t.Error("CheckAnnotation() considers /dev/zero valid.")
		}
	}
	defer fd.Close()

	// Only run this test if the descriptors file is there.
	if _, err = os.Stat(serverDescriptorFile); err == nil {

		fd, err := os.Open(serverDescriptorFile)
		if err != nil {
			return
		}
		defer fd.Close()

		err = CheckAnnotation(fd, descriptorAnnotations)
		if err != nil {
			t.Error("CheckAnnotation() failed to accept annotation: ", err)
		}
		fd.Seek(0, 0)

		err = CheckAnnotation(fd, consensusAnnotations)
		if err == nil {
			t.Error("CheckAnnotation() failed to reject annotation.")
		}
	}

	// Only run this test if the consensus file is there.
	if _, err = os.Stat(consensusFile); err == nil {

		fd, err := os.Open(consensusFile)
		if err != nil {
			return
		}
		defer fd.Close()

		err = CheckAnnotation(fd, consensusAnnotations)
		if err != nil {
			t.Error("CheckAnnotation() failed to accept annotation: ", err)
		}
		fd.Seek(0, 0)

		err = CheckAnnotation(fd, descriptorAnnotations)
		if err == nil {
			t.Error("CheckAnnotation() failed to reject annotation.")
		}
	}
}
