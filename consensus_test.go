// Tests functions from "consensus.go".

package zoossh

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Benchmark the time it takes to parse a consensus file.
func BenchmarkConsensusParsing(b *testing.B) {

	// Only run this benchmark if the consensus file is there.
	if _, err := os.Stat(consensusFile); err == nil {
		for i := 0; i < b.N; i++ {
			ParseConsensusFile(consensusFile)
		}
	}
}

// Benchmark the time it takes to lazily parse a consensus file.
func BenchmarkLConsensusParsing(b *testing.B) {

	// Only run this benchmark if the consensus file is there.
	if _, err := os.Stat(consensusFile); err == nil {
		for i := 0; i < b.N; i++ {
			LazilyParseConsensusFile(consensusFile)
		}
	}
}

// Benchmark the time it takes to parse a consensus file and get all its router
// statuses.
func BenchmarkConsensusParsingAndGetting(b *testing.B) {

	// Only run this benchmark if the consensus file is there.
	if _, err := os.Stat(consensusFile); err == nil {
		for i := 0; i < b.N; i++ {
			consensus, _ := ParseConsensusFile(consensusFile)
			for fingerprint, _ := range consensus.RouterStatuses {
				consensus.Get(fingerprint)
			}
		}
	}
}

// Benchmark the time it takes to lazily parse a consensus file and get all its
// router statuses.
func BenchmarkLConsensusParsingAndGetting(b *testing.B) {

	// Only run this benchmark if the consensus file is there.
	if _, err := os.Stat(consensusFile); err == nil {
		for i := 0; i < b.N; i++ {
			consensus, _ := LazilyParseConsensusFile(consensusFile)
			for fingerprint, _ := range consensus.RouterStatuses {
				consensus.Get(fingerprint)
			}
		}
	}
}

func TestConsensusOperations(t *testing.T) {

	validFingerprint1 := Fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	validFingerprint2 := Fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	invalidFingerprint := Fingerprint("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	// Get a fresh consensus.
	consensus := NewConsensus()
	if consensus.Length() != 0 {
		t.Error("Consensus should be of size zero.")
	}

	// Fingerprints should always be stored in upper case format.
	consensus.Set(validFingerprint1, &RouterStatus{})
	consensus.Set(validFingerprint2, &RouterStatus{})
	if consensus.Length() != 1 {
		t.Error("Consensus should be of size one.")
	}

	status, exists := consensus.Get(validFingerprint2)
	if !exists {
		t.Error("Could not retrieve fingerprint which should be available.")
	}

	if status.ORPort != 0 {
		t.Error("Field ORPort should be 0.")
	}

	status, exists = consensus.Get(invalidFingerprint)
	if exists || (status != nil) {
		t.Error("Retrieved fingerprint which should not exist.")
	}
}

func TestStatusParsing(t *testing.T) {

	_, _, err := ParseRawStatus("invalid router status")
	if err != nil {
		t.Error("Invalid router status did not raise an error.")
	}
}

func TestConsensusSetOperations(t *testing.T) {

	fingerprint0, getStatus0, err := ParseRawStatus(`r Karlstad0 m5TNC3uAV+ryG6fwI7ehyMqc5kU f1g9KQhgS0r6+H/7dzAJOpi6lG8 2014-12-08 06:57:54 193.11.166.194 9000 80
s Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.2.4.23
w Bandwidth=2670
p reject 1-65535`)
	if err != nil {
		t.Error(err)
	}

	fingerprint1, getStatus1, err := ParseRawStatus(`r Karlstad1 zO8CqkVMCrD+GsaDBPbYxCIMGRI pR21zIq4gZQmZOj2FvRwNO5U+K0 2014-12-08 06:57:49 193.11.166.194 9001 0
s Fast Guard Running Stable Valid
v Tor 0.2.4.23
w Bandwidth=2290
p reject 1-65535`)
	if err != nil {
		t.Error(err)
	}

	fingerprint2, getStatus2, err := ParseRawStatus(`r Karlstad2 e9hMtjhF4NYcHPqDkUobjJaEgrE eu8/9NajsgwD6+/vlObfyk2bZjo 2014-12-08 12:24:43 81.170.149.212 9001 0
s Fast Running Stable Valid
v Tor 0.2.3.25
w Bandwidth=778
p reject 1-65535`)
	if err != nil {
		t.Error(err)
	}

	if strings.ToUpper(string(fingerprint1)) != "CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912" {
		t.Error("Unexpected fingerprint for router status.")
	}

	if getStatus1().ORPort != 9001 {
		t.Error("Unexpected ORPort.")
	}

	consensus0 := NewConsensus()
	consensus0.Set(fingerprint0, getStatus0())
	consensus1 := NewConsensus()
	consensus1.Set(fingerprint0, getStatus0())
	consensus1.Set(fingerprint1, getStatus1())
	consensus1.Set(fingerprint2, getStatus2())
	consensus2 := NewConsensus()
	consensus2.Set(fingerprint2, getStatus2())

	intersect := consensus0.Intersect(consensus1)
	if intersect.Length() != 1 {
		t.Error("Bad consensus intersection.")
	}
}

func TestExtractStatusEntry(t *testing.T) {

	goodStatusEntry := `
r seele AAoQ1DAR6kkoo19hBAX5K0QztNw bdrzhG0Kk/8DUsnSdmzj7DjFQjY 2014-12-08 12:27:05 73.15.150.172 9001 0
s Fast Running Stable Valid
v Tor 0.2.5.10
w Bandwidth=18
p reject 1-65535
`

	signature := "directory-signature 5420FD8EA46BD4290F1D07A1883C9D85ECC486C4 CCB7170F6B270B44301712DD7BC04BF9515AF374"

	s, done, err := extractStatusEntry(goodStatusEntry + signature)
	if err != nil {
		t.Error("Failed to extract valid status entry.", err)
	}

	if strings.TrimSpace(s) != strings.TrimSpace(goodStatusEntry) {
		t.Error("Failed to extract correct status entry.")
	}

	if done != true {
		t.Error("Failed to state that extraction is done.")
	}

	s, done, err = extractStatusEntry(goodStatusEntry + "\nr foo" + signature)
	if done == true {
		t.Error("Failed to state that extraction is not yet done.")
	}
}

func TestExtractMetaInfo(t *testing.T) {

	consensus := NewConsensus()
	if _, err := os.Stat(consensusFile); err != nil {
		return
	}

	fd, err := os.Open(consensusFile)
	if err != nil {
		t.Error(err)
	}

	extractMetaInfo(fd, consensus)
	if consensus.ValidAfter != time.Date(2014, time.December, 8, 16, 0, 0, 0, time.UTC) {
		t.Error("ValidAfter time in consensus invalid.")
	}
	if consensus.FreshUntil != time.Date(2014, time.December, 8, 17, 0, 0, 0, time.UTC) {
		t.Error("FreshUntil time in consensus invalid.")
	}
	if consensus.ValidUntil != time.Date(2014, time.December, 8, 19, 0, 0, 0, time.UTC) {
		t.Error("ValidUntil time in consensus invalid.")
	}
}

func TestConsensusToSlice(t *testing.T) {

	// Only run this benchmark if the consensus file is there.
	if _, err := os.Stat(consensusFile); err == nil {
		consensus, err := ParseConsensusFile(consensusFile)
		if err != nil {
			t.Fatal(err)
		}

		consensusSlice := consensus.ToSlice()
		if consensus.Length() != len(consensusSlice) {
			t.Error("Consensus slice length differs from map length.")
		}

		for _, getStatus := range consensusSlice {
			status := getStatus()
			if _, found := consensus.Get(status.Fingerprint); !found {
				t.Error("Router status in slice not found in map.")
			}
		}
	}
}
