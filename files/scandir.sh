#!/usr/bin/env bash

# find all files in /scandir with a .tcl or .irule extension
# scan them with irulescan
# then print results in simplistic yaml

echo "---"
IFS=$'\n';
for filename in $(find /scandir -type f | grep -i -e '\.tcl$' -e '\.irule$' | sort); do
    echo "${filename#/scandir}: |"
    for line in $(irulescan check $filename);
    do
        echo "  $line"
    done
done
