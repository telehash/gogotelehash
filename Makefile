
build:
	go get -v '.'

examples:
	go get -v './_examples/telehash-ping'
	go get -v './_examples/telehash-seed'

test: build
	go test -v '.'

test-profile: build
	go test -c '.'
	./gogotelehash.test -test.cpuprofile=cpu.prof -test.run="TestOpen"
	go tool pprof --web gogotelehash.test cpu.prof
	rm gogotelehash.test cpu.prof

.PHONEY: build test examples
