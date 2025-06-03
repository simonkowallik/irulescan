#!/bin/bash

function run-cmd-in-path {
    path=$1
    shift
    cmd=$@
    start_dir=$(pwd)
    if [[ ! -d "$path" ]]; then
        echo "Path $path does not exist."
        exit 1
    fi
    echo -n "running $cmd in $path:"
    cd "$path"
    eval "$cmd"
    if [[ $? -ne 0 ]]; then
        echo "FAIL"
        exit 1
    fi
    cd "$start_dir"
}

function run-all-cli-checkref-tests {
    start_dir=$(pwd)
    failures=0
    IFS=$'\n'
    for file in $(find . |grep -e '.tcl$' -e '.irule$'); do
        echo "cd "$(dirname "$file")" for $file"
        cd "$(dirname "$file")"
        tcl_file="$(basename "$file")"
        json_file="$(basename "$file").json"
        if [[ -f "$json_file" ]]; then
            # to update the json file, uncomment the next lines
            #echo irulescan check "$tcl_file" | jq . > "$json_file"
            #irulescan check "$tcl_file" | jq . > "$json_file"

            echo -n "running test: ($(pwd)/ $tcl_file/$json_file): "
            irulescan checkref "$json_file"
            if [[ $? -ne 0 ]]; then
                echo "fail"
                failures=$((failures + 1))
            fi
            irulescan check -r "$json_file" "$tcl_file"
            if [[ $? -ne 0 ]]; then
                echo "fail"
                failures=$((failures + 1))
            fi
        #else
        #    echo "skipping test: $file: no json file found"
        fi
        cd "$start_dir"
    done
    echo "* total failures: $failures"
    if [[ $failures -ne 0 ]]; then
        echo "FAIL"
        #exit 1
    fi
}

function run-cli-checkref-test {
    if [[ $# -ne 2 ]]; then
        echo "Usage: $0 <path_to_test> <file_name.json>"
        exit 1
    fi

    path_to_test=$1
    file_name=$2

    if [[ ! -f "$path_to_test/$file_name" ]]; then
        echo "File $path_to_test/$file_name does not exist."
        exit 1
    fi

    start_dir=$(pwd)
    cd "$path_to_test"
    json_file="$file_name"

    echo -n "running test: $json_file: "
    irulescan checkref $CHECKREF_OPTIONS "$json_file"

    if [[ $? -ne 0 ]]; then
        echo "FAIL"
        exit 1
    fi
    cd "$start_dir"
    return 0
}


function run-cli-tests {
    if ! command -v jd &> /dev/null; then
        echo "jd required but not installed. Skipping tests."
        exit
    fi
    start_dir=$(pwd)
    failures=0
    for file in $(find . |grep -e '.tcl$' -e '.irule$'); do
        cd "$(dirname "$file")"
        json_file="$(basename "$file").json"
        if [[ -f "$json_file" ]]; then
            echo -n "running test: $json_file: "
            irulescan check "$file" > output.json
            jd -mset output.json "$json_file" || ( echo "fail" && failures=$((failures + 1)) )
            rm -f output.json
        else
            echo "skipping test: $file: no json file found"
        fi
        cd "$start_dir"
    done
    echo "* total failures: $failures"
    if [[ $failures -ne 0 ]]; then
        echo "FAIL"
        exit 1
    fi
}

function test_container_stdin {
    echo -n "test_container_stdin: "
    cat tests/basic/dangerous.tcl | docker run --rm -i -v "${PWD}/tests:/scandir/tests" \
        irulescan:latest check -r 'tests/basic/dangerous.tcl.stdin.json' - > output.json
    [[ "$(<output.json)" == "OK" ]] || ( echo "fail" && exit 1 )
    echo "OK"
}

function test_scandir_multi_file {
    echo -n "test_scandir_multi_file: "
    docker run --rm -v ${PWD}/tests/basic:/scandir \
    irulescan:latest > output.json
    jd -mset output.json tests/basic/irulescan.json || ( echo "fail" && exit 1 )
    echo "OK"
}

function test_apiserver_multi_file {
    irulescan apiserver --listen 127.0.0.1:8888 >/dev/null &

    echo -n "test_apiserver_multi_file: "
    sleep 1
    curl -s http://localhost:8888/scanfiles/ \
        -F 'file=@basic/ok.tcl' \
        -F 'file=@basic/warning.tcl' \
        -F 'file=@basic/dangerous.tcl' > output.json
    jd -mset output.json basic/irulescan.json || ( echo "FAIL" && rm -f output.json && exit 1 )
    rm -f output.json
    echo "OK"
    sleep 1
    kill $(jobs -p) > /dev/null
}

function test_apiserver_plain_code {
    irulescan apiserver --listen 127.0.0.1:8888 >/dev/null &

    echo -n "test_apiserver_plain_code: "
    sleep 1
    curl -s http://localhost:8888/scan/ \
    --data-binary '@basic/dangerous.tcl' -o output.json
    jd -mset output.json basic/dangerous.tcl.stdin.json || ( echo "FAIL" && rm -f output.json && exit 1 )
    rm -f output.json
    echo "OK"
    sleep 1
    kill $(jobs -p) > /dev/null
}

# tests

# apiserver tests
test_apiserver_plain_code
test_apiserver_multi_file

# run specific checkref tests
CHECKREF_OPTIONS="" run-cli-checkref-test ./basic irulescan.json
CHECKREF_OPTIONS="--no-warn" run-cli-checkref-test ./basic irulescan_nowarn.json

# run all checkref tests
run-all-cli-checkref-tests

# run specific cli tests
run-cmd-in-path ./basic irulescan check --exclude-empty-findings -r irulescan_exclude_empty.json .

# backtrace on invalid operator token in expression
run-cmd-in-path ./issues irulescan check 7.tcl 2> &1 | grep -qe 'ERROR: Invalid Operator token "SomeInvalidOperator"'
if [[ $? -ne 0 ]]; then
    echo "FAIL"
    exit 1
fi