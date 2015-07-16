#!/bin/bash
#
# This script fetches a bunch of files which are used for zoossh's tests.  So
# if you don't hack on zoossh and test the code base, there's no need to run
# this script.

NAME="zoossh"

echo "Downloading network status and server descriptors to test ${NAME}."

mkdir -p "/tmp/collector-descriptors/server-descriptors-2014-11/8/8/"
mkdir -p "/tmp/collector-descriptors/server-descriptors-2014-12/7/a/"
wget -nv "https://nymity.ch/zoossh/7aef3ff4d6a3b20c03ebefef94e6dfca4d9b663a" \
	-O "/tmp/collector-descriptors/server-descriptors-2014-12/7/a/7aef3ff4d6a3b20c03ebefef94e6dfca4d9b663a"
wget -nv "https://nymity.ch/zoossh/88827c73d5fd35e9638f820c44187ccdf8403b0f" \
	-O "/tmp/collector-descriptors/server-descriptors-2014-11/8/8/88827c73d5fd35e9638f820c44187ccdf8403b0f"
wget -nv "https://nymity.ch/zoossh/server-descriptors" -O /tmp/server-descriptors
wget -nv "https://nymity.ch/zoossh/consensus" -O /tmp/consensus
