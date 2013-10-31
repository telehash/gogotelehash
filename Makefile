
build:
	go get -v '.'

test: build
	go test -v '.'

.PHONEY: build test
