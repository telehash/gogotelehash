
build:
	go get -v '.'

examples:
	go get -v './_examples/telehash-ping'

test: build
	go test -v '.'

.PHONEY: build test examples
