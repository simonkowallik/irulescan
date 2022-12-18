#!/usr/bin/env bash

# find all files in /scandir with a .tcl or .irule extension
# scan them with irulescan
# then print results in simplistic yaml

echo "---"
for filename in $(find /scandir -type f | grep -i -e '\.tcl$' -e '\.irule$'); do
    echo "${filename}: |"
    IFS=$'\n';
    for line in $(irulescan check $filename);
    do
        echo "  $line"
    done
done
