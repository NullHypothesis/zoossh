![zoossh logo](https://nullhypothesis.github.com/zoossh_logo.png)
=================================================================

[![Build Status](https://travis-ci.org/NullHypothesis/zoossh.svg?branch=master)](https://travis-ci.org/NullHypothesis/zoossh)

Overview
--------
Zoossh is a Go parsing library for Tor-specific data formats.  It can parse
consensuses and server descriptors.  I originally wrote zoossh as a speedy
fundament for [sybilhunter](https://github.com/NullHypothesis/sybilhunter), a
tool to find Sybils in the Tor network.  I have no need for other file types, so
if zoossh doesn't provide what you need, check out the libraries below.

Supported file formats
----------------------
Zoossh partially supports the following two file formats:

* Server descriptors (`@type server-descriptor 1.0`)
* Network status consensuses (`@type network-status-consensus-3 1.0`)

For more information about file formats, have a look at
[CollecTor](https://collector.torproject.org/#data-formats).

Examples
--------
Here's how you can parse a network status document and iterate over all relay
statuses:

    consensus, err := zoossh.ParseConsensusFile(fileName)
    if err != nil {
        // Handle error.
    }

    for status := range consensus.Iterate(nil) {
        fmt.Println(status)
    }

Similarly, here's how you can parse a file containing server descriptors:

    descriptors, err := zoossh.ParseDescriptorFile(fileName)
    if err != nil {
        // Handle error.
    }

    for desc := range descriptors.Iterate(nil) {
        fmt.Println(desc)
    }

For more details, have a look at zoossh's
[GoDoc page](https://godoc.org/github.com/NullHypothesis/zoossh).

Alternatives
------------
Check out the Python library [Stem](https://stem.torproject.org) or the Java
library [metrics-lib](https://gitweb.torproject.org/metrics-lib.git).  Both
have more comprehensive support for data formats.  There is also a
[comparison available online](https://stem.torproject.org/tutorials/mirror_mirror_on_the_wall.html#are-there-any-other-parsing-libraries)
between Stem, metrics-lib, and zoossh.

Contact
-------
Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
