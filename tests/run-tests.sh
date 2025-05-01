#!/bin/bash

function run-cli-tests-checkref {
    start_dir=$(pwd)
    failures=0
    for file in $(find . |grep -e '.tcl$' -e '.irule$'); do
        cd "$(dirname "$file")"
        json_file="$(basename "$file").json"
        if [[ -f "$json_file" ]]; then
            echo -n "running test: $json_file: "
            irulescan checkref "$json_file"
            if [[ $? -ne 0 ]]; then
                echo "fail"
                failures=$((failures + 1))
            fi
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

function run-cli-tests {
    if ! command -v jd &> /dev/null; then
        echo "jq required but not installed. Skipping tests."
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

function build-container-apiserver {
    docker build -t irulescan:apiserver -f files/Dockerfile.apiserver .
}

function prepare-container-latest {
    docker image inspect irulescan:latest > /dev/null 2>&1 || docker build -t irulescan:latest -f files/Dockerfile .
}

function prepare-apiserver {
    docker image inspect irulescan:apiserver > /dev/null 2>&1 || build-container-apiserver
    if [ -z "$(docker ps -q --filter ancestor=irulescan:apiserver)" ]; then
        echo -n "starting API server: "
        docker run -p 8000:8000 -d irulescan:apiserver
        sleep 5
    fi
}

function cleanup {
    if [ -n "$(docker ps -q --filter ancestor=irulescan:apiserver)" ]; then
        echo -n "stopping API server: "
        docker stop $(docker ps -q --filter ancestor=irulescan:apiserver)
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
    prepare-apiserver

    echo -n "test_apiserver_multi_file: "
    curl -s http://localhost:8000/scanfiles/ \
        -F 'file=@tests/basic/ok.tcl' \
        -F 'file=@tests/basic/warning.tcl' \
        -F 'file=@tests/basic/dangerous.tcl' > output.json
    jd -mset output.json tests/basic/irulescan.json || ( echo "fail" && exit 1 )
    echo "OK"
}

function test_apiserver_plain_code {
    prepare-apiserver

    echo -n "test_apiserver_plain_code: "
    curl -s http://localhost:8000/scan/ \
    --data-binary '@tests/basic/dangerous.tcl' > output.json
    jd -mset output.json tests/basic/dangerous.tcl.stdin.json || ( echo "fail" && exit 1 )
    echo "OK"
}


prepare-apiserver
prepare-container-latest

test_container_stdin
test_scandir_multi_file
test_apiserver_multi_file
test_apiserver_plain_code

cleanup

trap cleanup EXIT
