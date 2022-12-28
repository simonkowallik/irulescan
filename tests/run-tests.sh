#!/usr/bin/env bash

set -e

test -d ./tests || (echo "./tests directory not found. Run $0 from repo root." && exit 1)

IFS=$'\n';
for testfile in $(find tests/ -type f | grep -e '\.tcl$' | sort);
do
    echo "# $testfile"
    #irulescan check $testfile > $testfile.expected
    irulescan check $testfile | diff --ignore-blank-lines ${testfile}.expected -
done
