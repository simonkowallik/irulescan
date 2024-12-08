#!/bin/bash

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
        docker run --rm -p 8888:80 -d irulescan:apiserver
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
    jd -mset output.json tests/basic/irulescan_exclude_empty.json || ( echo "fail" && exit 1 )
    echo "OK"
}

function test_apiserver_multi_file {
    prepare-apiserver

    echo -n "test_apiserver_multi_file: "
    curl -s http://localhost:8888/scanfiles/ \
        -F 'file=@tests/basic/ok.tcl' \
        -F 'file=@tests/basic/warning.tcl' \
        -F 'file=@tests/basic/dangerous.tcl' > output.json
    jd -mset output.json tests/basic/irulescan.json || ( echo "fail" && exit 1 )
    echo "OK"
}

function test_apiserver_plain_code {
    prepare-apiserver

    echo -n "test_apiserver_plain_code: "
    curl -s http://localhost:8888/scan/ \
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
