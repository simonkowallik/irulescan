#!/usr/bin/env bash

set -e

if [[ "$0" == "/entrypoint.sh" ]];
then
    # entrypoint for apiserver testing
    uvicorn apiserver:app --host 0.0.0.0 --port 80 --log-level error &
    exec $@
elif [[ "$0" == "/test-apiserver.sh" ]];
then
    test -d ./tests || (echo "./tests directory not found. Run $0 from repo root." && exit 1)

    DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null && apt-get install -y curl > /dev/null

    echo; echo "* running apiserver tests"
    echo "# api endpoint: /scan/"
    IFS=$'\n';
    for testfile in $(find tests/basic/ -type f | grep -e '\.expected$' | sort);
    do
        echo "# $testfile"
        curl -s http://localhost/scan/ --data-binary @${testfile%.expected} \
        | diff --ignore-blank-lines ${testfile} -
    done

    echo "# api endpoint: /scanfiles/"
    curl -s http://localhost/scanfiles/ \
        -F 'file=@tests/basic/ok.tcl' \
        -F 'file=@tests/basic/warning.tcl' \
        -F 'file=@tests/basic/dangerous.tcl' \
        | diff -u --ignore-blank-lines tests/basic.json -
else
    test -d ./tests || (echo "./tests directory not found. Run $0 from repo root." && exit 1)

    echo "* running standard tests"

    IFS=$'\n';
    for testfile in $(find tests/ -type f | grep -e '\.expected$' | sort);
    do
        echo "# $testfile"
        #irulescan check ${testfile%.expected} > $testfile
        irulescan check ${testfile%.expected} | diff -u --ignore-blank-lines ${testfile} -
    done
fi

echo "*** success ***"
