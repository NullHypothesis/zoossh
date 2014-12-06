![zoossh logo](https://nullhypothesis.github.com/zoossh_logo.png)

Overview
--------
`zoossh` is a parser written in Go for Tor-specific data formats.  In case you
are wondering, "zoossh" is the sound it makes when such documents are parsed!
Though admittedly, the speed mostly comes from `zoossh` being implemented in a
compiled language and not because the parsing code is particularly
sophisticated.

Supported file formats
----------------------
The following file formats are currently partially supported.  For more
information about file formats, have a look at
[CollecTor](https://collector.torproject.org/formats.html).

* Server descriptors (`@type server-descriptor 1.0`)
* Network status consensuses (`@type network-status-consensus-3 1.0`)

Examples
--------
Here's how you can parse a network status document and iterate over all relay
statuses:

    statuses, _ := zoossh.ParseConsensusFile(fileName)
    for _, status := range statuses {
        fmt.Println(status)
    }

Alternatives
------------
Check out the Python library [Stem](https://stem.torproject.org) or the Java
library [metrics-lib](https://gitweb.torproject.org/metrics-lib.git).

Contact
-------
Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
