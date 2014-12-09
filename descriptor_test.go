// Tests functions from "descriptor.go".

package zoossh

import (
	"testing"
)

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

	_, err := ParseRawDescriptor(goodDescriptor)
	if err != nil {
		t.Error("Failed to parse server descriptor.")
	}
}

// Test the function ParsePlatform().
func TestParsePlatform(t *testing.T) {

	goodVersionString := "Tor 0.2.5.10 on Linux"
	badVersionString := "foo bar foo"

	ver, os := ParsePlatform(goodVersionString)
	if (ver != "Tor 0.2.5.10") || (os != "Linux") {
		t.Error("Couldn't parse version string \"%s\".", goodVersionString)
	}

	ver, os = ParsePlatform(badVersionString)
	if (ver != "") || (os != "") {
		t.Error("Couldn't parse version string \"%s\".", badVersionString)
	}
}
