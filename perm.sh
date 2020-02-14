#!/bin/bash

bins="bpf_test"
cap_flag="cap_net_admin,cap_net_raw=eip"
if [ -n "$1" ]; then
	if [ "$1" == "allow_ptr_leaks" ]; then
		cap_flag="cap_sys_admin,$cap_flag"
	fi
fi

echo "Requesting sudo for linux capability permissions to binaries"
for bin in $bins; do
    echo sudo setcap $cap_flag $bin
    sudo setcap $cap_flag $bin
done
