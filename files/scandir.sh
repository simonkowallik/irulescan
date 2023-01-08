#!/usr/bin/env bash

# find all files in SCANDIR with a .tcl or .irule extension
# scan them with irulescan
# then print results in simplistic yaml

SCANDIR=$1

echo "---"
IFS=$'\n';
for filename in $(find $SCANDIR -type f | grep -i -e '\.tcl$' -e '\.irul$' -e '\.irule$' | sort); do
    echo "${filename#${SCANDIR}}: |"
    for line in $(irulescan check $filename);
    do
        echo "  $line"
    done
done
