// Tests functions from "descriptor.go".

package zoossh

import (
	"os"
	"strings"
	"testing"
)

// The number of unique fingerprints in the descriptor test file.  The number
// of total fingerprints is 867, but we don't store duplicates in our map.
const (
	numServerDescriptors = 763
)

// Benchmark the time it takes to parse a server descriptor file.
func BenchmarkDescriptorParsing(b *testing.B) {

	// Only run this benchmark if the descriptors file is there.
	if _, err := os.Stat(serverDescriptorFile); err == nil {
		for i := 0; i < b.N; i++ {
			ParseDescriptorFile(serverDescriptorFile)
		}
	}
}

// Test the function ParseRawDescriptor().
func TestDescriptorParsing(t *testing.T) {

	// A random and valid server descriptor.
	goodDescriptor := `@type server-descriptor 1.0
router LetFreedomRing 24.233.74.111 9001 0 0
platform Tor 0.2.6.1-alpha on Linux
protocols Link 1 2 Circuit 1
published 2014-12-05 22:01:13
fingerprint DA4D EC93 C8D2 F187 C027 A96D 3925 C153 1D90 A89E
uptime 339587
bandwidth 20480 20480 16996
extra-info-digest 15FA36289DD75D89B389CED0BE23D80FB50629BD
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALD6Dbj1okBj4mmz/sCgIGFJk/CTWlMsT3CS1kP7Q2gAaDewEbo1+me3
X5f3QpvZ9Yh2l5Q+btU4a/Yib3pg/KhyX96Z5zrvz9dGPPXGORpwawMIH7Aa+jtp
v2l0misfGCloIamfI5dzayTu9gR4emuKm34tipkfIz6hLkO7xW1nAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM6sVv1ASHBuLe8l3+cF4xATk1n/CqNRqML0Gra0S9UaBnKakm9tk7Vw
PJifL3B318lRDjAE2wTVyM+437TLaROLNBrQOF2apjgJYH661vPFG5Uw6+8CXv6w
tHeXU1pvc/E7SA0IpUjm80z0HhSA3oGwuP4IEB1U1IxxiJNFaBk7AgMBAAE=
-----END RSA PUBLIC KEY-----
hidden-service-dir
contact 0xCDD0190B Craig Andrews <candrews@integralblue.com>
ntor-onion-key q8Qg9PaoBm59j7cEJcOrzTUazVt3D8Ax4L3oaO8PaxU=
reject 0.0.0.0/8:*
reject 169.254.0.0/16:*
reject 127.0.0.0/8:*
reject 192.168.0.0/16:*
reject 10.0.0.0/8:*
reject 172.16.0.0/12:*
reject 24.233.74.111:*
accept *:22
accept *:465
accept *:993
accept *:994
accept *:995
accept *:6660-6697
reject *:*
router-signature
-----BEGIN SIGNATURE-----
vKWlPhEDoRHOKgDNXE07HFl39b4SmGUDo8DStSzzza+CKVw2RnV41wYBpjRJvu2Q
VcQb00bfqWP/DK38GmVMgzKRZ7e1k2TpzaeL3ssD3gS6wJPzbIbcL++yUhtPukk/
tWJ53g/ru8Hiy+h9Wa5gI+Eog/z4hj36GBiaTXJoG3M=
-----END SIGNATURE-----
`

	_, _, err := ParseRawDescriptor(goodDescriptor)
	if err != nil {
		t.Error("Failed to parse server descriptor.")
	}
}

// Test the function extractDescriptor().
func TestExtractDescriptor(t *testing.T) {

	goodDescriptor := `
router leenuts 46.14.245.206 9001 0 0
platform Tor 0.2.4.24 on Linux
protocols Link 1 2 Circuit 1
published 2014-12-08 14:01:26
fingerprint F8E9 F7D3 0ED7 F541 FD24 8945 FAA2 B593 AD5E 584D
uptime 86315
bandwidth 153600 204800 0
extra-info-digest 218F94A27A33285CF3BFE9E8A737CCE91503AC53
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL+3UeGGF7xExy3z58T3Xu9uWabYpmub5bATZ+yLia9crsLrLEIaAsJ9
oa3XMbC1bOL0FBJj6WhrFJvwDw49yGKze5b9n8e4SRsZANLzkUr9vLmhXLnnkfvs
rBu1PNDpBaQjQ2AviEwwWcJjf4imUtlsv94M5F/NEO1E1LyU/rDPAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL7ZgD+iMdXECit8bkXInwwvLbVg8fbZ352CvzGdW38nCYj5yo+tv7Vc
/gYknyKSjUKslfz7cE7Ez8ssWY3ijHQzrguRFyIC4iYDR9gW/Ko1ea8E9du5prxq
7vJXKjPtze2AMqauABmCjBE6RlT3tPBy1NrklYDy8T7q4qoTVXO9AgMBAAE=
-----END RSA PUBLIC KEY-----
hibernating 1
hidden-service-dir
ntor-onion-key 8tAylcNZrA23N3iBPMsHGB8AYz9iHwqgaS6qAx3qVxA=
reject *:*
router-signature
-----BEGIN SIGNATURE-----
niSWXFuWh/U/iyHzGa69mNynIKlkXA953Rs+vSfGcX7FMZ7/aMp3w/FcU9GQsgbt
POl7qz1m+xho4CJnhlMqLhomUas7AZ02jvIvMlKajw51nhM+eFwl3hwlTyAJ0tov
Oa5fhjBu72rul97Aa4bJPZKa+RJNCGUKJuFGoAlZV7I=
-----END SIGNATURE-----
`

	s, done, err := extractDescriptor("foo" + goodDescriptor)
	if err != nil {
		t.Error("Failed to extract good server descriptor.")
	}

	if strings.TrimSpace(s) != strings.TrimSpace(goodDescriptor) {
		t.Error("Failed to extract correct server descriptor.")
	}

	if done != true {
		t.Error("Failed to state that extraction was done.")
	}

	s, done, err = extractDescriptor(goodDescriptor + "foo")
	if done != false {
		t.Error("Failed to state that extraction was not done.")
	}

	s, done, err = extractDescriptor(goodDescriptor[:1136])
	if err == nil {
		t.Error("Failed to reject incomplete server descriptor.")
	}
}

func TestNewRouterDescriptor(t *testing.T) {

	desc := NewRouterDescriptor()
	if desc.Family == nil {
		t.Error("Family map is not initialised.")
	}
}

func TestNewRouterDescriptors(t *testing.T) {

	descs := NewRouterDescriptors()
	if descs.RouterDescriptors == nil {
		t.Error("RouterDescriptors map is not initialised.")
	}
}

func TestString(t *testing.T) {

	desc := NewRouterDescriptor()
	if len(desc.String()) == 0 {
		t.Error("Empty string for String() method returned.")
	}
}

func TestDescriptorsToSlice(t *testing.T) {

	// Only run this benchmark if the descriptors file is there.
	if _, err := os.Stat(serverDescriptorFile); err == nil {
		descs, err := ParseDescriptorFile(serverDescriptorFile)
		if err != nil {
			t.Fatal(err)
		}

		descSlice := descs.ToSlice()
		if descs.Length() != len(descSlice) {
			t.Error("Descriptor slice length differs from map length.")
		}

		for _, getDesc := range descSlice {
			desc := getDesc()
			if _, found := descs.Get(desc.Fingerprint); !found {
				t.Error("Descriptor in slice not found in map.")
			}
		}
	}
}
