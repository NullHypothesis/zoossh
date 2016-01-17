// Tests functions from "generic.go".

package zoossh

import (
	"net"
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

func TestInterfaces(t *testing.T) {

	testFingerprint := Fingerprint("9695DFC35FFEB861329B9F1AB04C46397020CE31")

	if _, err := os.Stat(consensusFile); err != nil {
		return
	}

	if _, err := os.Stat(serverDescriptorFile); err != nil {
		return
	}

	consensus, err := ParseUnknownFile(consensusFile)
	if err != nil {
		t.Fatal(err)
	}

	descriptors, err := ParseUnknownFile(serverDescriptorFile)
	if err != nil {
		t.Fatal(err)
	}

	// Test the GetObject() function.
	obj1, found := consensus.GetObject(testFingerprint)
	if found != true {
		t.Error("Could not find existing router status in consensus.")
	}

	obj2, found := descriptors.GetObject(testFingerprint)
	if found != true {
		t.Error("Could not find existing descriptor in descriptor set.")
	}

	// Test the GetFingerprint() function.
	if obj1.GetFingerprint() != testFingerprint {
		t.Error("Failed to retrieve correct fingerprint.")
	}

	if obj2.GetFingerprint() != testFingerprint {
		t.Error("Failed to retrieve correct fingerprint.")
	}

	// Test the Length() function.
	if consensus.Length() != numRouterStatuses {
		t.Error("Failed to determine consensus length.")
	}

	if descriptors.Length() != 763 {
		t.Error("Failed to determine descriptor set length.")
	}

	// Test the Iterate() function.
	counter := 0
	for _ = range consensus.Iterate(nil) {
		counter += 1
	}
	if counter != consensus.Length() {
		t.Error("Failed to iterate over all router statuses in consensus.")
	}

	counter = 0
	for _ = range descriptors.Iterate(nil) {
		counter += 1
	}
	if counter != descriptors.Length() {
		t.Error("Failed to iterate over all descriptors in descriptor set.")
	}

	// Test the Merge() function.
	prevLength := consensus.Length()
	consensus.Merge(consensus)
	if consensus.Length() != prevLength {
		t.Error("Consensus merge with itself caused unexpected length.")
	}

	prevLength = descriptors.Length()
	descriptors.Merge(descriptors)
	if descriptors.Length() != prevLength {
		t.Error("Descriptors merge with itself caused unexpected length.")
	}
}

func TestIsEmpty(t *testing.T) {

	filter := NewObjectFilter()
	if !filter.IsEmpty() {
		t.Error("Empty filter apparently not empty.")
	}

	filter.AddIPAddr(net.IP("1.2.3.4"))
	if filter.IsEmpty() {
		t.Error("Populated filter apparently empty.")
	}
}

func TestFilterGetterSetter(t *testing.T) {

	filter := NewObjectFilter()
	fpr := Fingerprint("9B94CD0B7B8057EAF21BA7F023B7A1C8CA9CE645")
	ipAddrs := net.IP("1.2.3.4")
	nickname := "dummy-relay-nickname"

	exists := filter.HasFingerprint(fpr)
	if exists {
		t.Error("Non-existing fingerprint apparently in filter.")
	}

	filter.AddFingerprint(fpr)
	exists = filter.HasFingerprint(fpr)
	if !exists {
		t.Error("Existing fingerprint apparently not in filter.")
	}

	exists = filter.HasIPAddr(ipAddrs)
	if exists {
		t.Error("Non-existing IP address apparently in filter.")
	}

	filter.AddIPAddr(ipAddrs)
	exists = filter.HasIPAddr(ipAddrs)
	if !exists {
		t.Error("Existing IP address apparently not in filter.")
	}

	exists = filter.HasNickname(nickname)
	if exists {
		t.Error("Non-existing nickname apparently in filter.")
	}

	filter.AddNickname(nickname)
	exists = filter.HasNickname(nickname)
	if !exists {
		t.Error("Existing nickname apparently not in filter.")
	}
}

func TestConsensusFiltering(t *testing.T) {

	if _, err := os.Stat(consensusFile); err != nil {
		return
	}

	consensus, err := ParseConsensusFile(consensusFile)
	if err != nil {
		t.Fatal(err)
	}

	filter := NewObjectFilter()
	filter.AddFingerprint(Fingerprint("9B94CD0B7B8057EAF21BA7F023B7A1C8CA9CE645"))
	filter.AddFingerprint(Fingerprint("CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912"))
	count := 0
	for _ = range consensus.Iterate(filter) {
		count++
	}
	if count != 2 {
		t.Error("Didn't filter correct amount of relays.")
	}

	count = 0
	for _ = range consensus.Iterate(nil) {
		count++
	}
	if count != numRouterStatuses {
		t.Error("Processed unexpected number of router statuses.")
	}

	count = 0
	for _ = range consensus.Iterate(NewObjectFilter()) {
		count++
	}
	if count != numRouterStatuses {
		t.Error("Processed unexpected number of router statuses.")
	}
}

func TestDescriptorFiltering(t *testing.T) {

	if _, err := os.Stat(serverDescriptorFile); err != nil {
		return
	}

	descriptors, err := ParseDescriptorFile(serverDescriptorFile)
	if err != nil {
		t.Fatal(err)
	}

	filter := NewObjectFilter()
	filter.AddNickname("leenuts")
	filter.AddNickname("manningsnowden2")
	count := 0
	for _ = range descriptors.Iterate(filter) {
		count++
	}
	if count != 2 {
		t.Error("Didn't filter correct amount of relays.")
	}

	count = 0
	for _ = range descriptors.Iterate(nil) {
		count++
	}
	if count != numServerDescriptors {
		t.Error("Processed unexpected number of router descriptors.", count)
	}

	count = 0
	for _ = range descriptors.Iterate(NewObjectFilter()) {
		count++
	}
	if count != numServerDescriptors {
		t.Error("Processed unexpected number of router descriptors.", count)
	}
}
