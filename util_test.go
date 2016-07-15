// Tests functions from "util.go".

package zoossh

import (
	"os"
	"testing"
	"time"
)

// Run the file "setup_tests.sh" in the scripts/ directory to obtain these
// files.
const (
	serverDescriptorDir  = "/tmp/collector-descriptors/"
	serverDescriptorFile = "/tmp/server-descriptors"
	consensusFile        = "/tmp/consensus"
)

// Benchmark the time it takes to look up a descriptor.
func BenchmarkDescriptorLookup(b *testing.B) {

	digest := "88827c73d5fd35e9638f820c44187ccdf8403b0f"
	date := time.Date(2014, time.December, 10, 0, 0, 0, 0, time.UTC)

	// Only run this benchmark if the descriptors file is there.
	if _, err := os.Stat(serverDescriptorDir); err == nil {
		for i := 0; i < b.N; i++ {
			LoadDescriptorFromDigest(serverDescriptorDir, digest, date)
		}
	}
}

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

// Test the function parseAnnotation().
func TestParseAnnotation(t *testing.T) {

	goodTests := []struct {
		s        string
		expected Annotation
	}{
		{"@type server-descriptor 1.0", Annotation{"server-descriptor", "1", "0"}},
		{"@type server-descriptor 1.2", Annotation{"server-descriptor", "1", "2"}},
		{"@type server-descriptor 2.0", Annotation{"server-descriptor", "2", "0"}},
		{"@type extra-info 2.0", Annotation{"extra-info", "2", "0"}},
		{"@type CASE 1.0", Annotation{"CASE", "1", "0"}},
	}
	badTests := []string{
		"",
		"@type test",
		"@type 1.0",
		"@type test 1",
		"@type test 1.",
		"@type test .0",
		"@type test 1.0 more",
		"@TYPE test 1.0",
		"@typo test 1.0",
		"type test 1.0",
	}

	for _, test := range goodTests {
		annotation, err := parseAnnotation(test.s)
		if err != nil {
			t.Errorf("%q resulted in an error: %s", test.s, err)
		}
		if !annotation.Equals(&test.expected) {
			t.Errorf("%q did not compare equal to %q", test.s, test.expected)
		}
	}

	for _, s := range badTests {
		_, err := parseAnnotation(s)
		if err == nil {
			t.Errorf("%q resulted in no error", s)
		}
	}
}

// Benchmark the function parseAnnotation().
func BenchmarkParseAnnotation(b *testing.B) {

	for i := 0; i < b.N; i++ {
		parseAnnotation("@type server-descriptor 1.0")
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
			t.Fatalf("GetAnnotation() failed to fetch annotation from \"%s\".", serverDescriptorFile)
		}

		if !annotation.Equals(expectedDescriptorAnnotation) {
			t.Errorf("Extracted annotation not as expected in \"%s\".", serverDescriptorFile)
		}
	}

	// Parse our provided consensus file which should work.
	if _, err := os.Stat(consensusFile); err == nil {
		annotation, err := GetAnnotation(consensusFile)
		if err != nil {
			t.Fatalf("GetAnnotation() failed to fetch annotation from \"%s\".", consensusFile)
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

func TestSanitiseFingerprint(t *testing.T) {

	if SanitiseFingerprint(" foo bar\n \t") != "FOO BAR" {
		t.Error("Fingerprint not sanitised successfully.")
	}
}

func TestLoadDescriptorFromDigest(t *testing.T) {

	_, err := LoadDescriptorFromDigest("", "foobar", time.Now())
	if err == nil {
		t.Error("Non-existant digest did not return error.")
	}

	date := time.Date(2014, 12, 8, 0, 0, 0, 0, time.UTC)
	if _, err := os.Stat(serverDescriptorDir); err == nil {
		desc, err := LoadDescriptorFromDigest(serverDescriptorDir,
			"7aef3ff4d6a3b20c03ebefef94e6dfca4d9b663a", date)
		if err != nil {
			t.Fatalf("Could not find and return descriptor.")
		}

		if desc.Fingerprint != Fingerprint("7BD84CB63845E0D61C1CFA83914A1B8C968482B1") {
			t.Error("Invalid descriptor returned.")
		}

		// Test previous month.
		desc, err = LoadDescriptorFromDigest(serverDescriptorDir,
			"88827c73d5fd35e9638f820c44187ccdf8403b0f", date)
		if err != nil {
			t.Fatalf("Could not find and return descriptor from previous month.")
		}

		if desc.Fingerprint != Fingerprint("7BD84CB63845E0D61C1CFA83914A1B8C968482B1") {
			t.Error("Invalid descriptor returned.")
		}
	}
}
