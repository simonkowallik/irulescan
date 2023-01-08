build:
	sudo docker build -t irulescan:latest -f files/Dockerfile .

build-apiserver:
	sudo docker build -t irulescan:apiserver -f files/Dockerfile.apiserver .

build-all: build build-apiserver

test:
	sudo docker run --rm -v ${PWD}:/scandir \
		irulescan:latest /scandir/tests/test.sh

test-apiserver:
	sudo docker run --rm \
		-v ${PWD}/tests/test.sh:/test-apiserver.sh \
		-v ${PWD}/tests/test.sh:/entrypoint.sh \
		--entrypoint /entrypoint.sh \
		-v ${PWD}/tests:/tests \
		irulescan:apiserver /test-apiserver.sh

test-all: test test-apiserver
