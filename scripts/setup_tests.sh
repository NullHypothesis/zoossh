#!/bin/bash
#
# This script fetches a bunch of files which are used for zoossh's tests.  So
# if you don't hack on zoossh and test the code base, there's no need to run
# this script.

NAME="zoossh"

echo "Downloading network status document to test ${NAME}."
wget -nv "http://www.nymity.ch/zoossh/server-descriptors" -O /tmp/server-descriptors
wget -nv "http://www.nymity.ch/zoossh/consensus" -O /tmp/consensus
