
build:
	go get -v '.'

examples:
	go get -v './_examples/telehash-ping'
	go get -v './_examples/telehash-seed'
	go get -v './_examples/go-interop-test'

test: build
	go test -v '.'

test-profile: build
	go test -c '.'
	./gogotelehash.test -test.cpuprofile=cpu.prof -test.run="TestOpen"
	go tool pprof --web gogotelehash.test cpu.prof
	rm gogotelehash.test cpu.prof

seed-deploy:
	# make examples
	GOOS=linux make examples
	# aws s3 cp --acl=public-read --region=us-east-1 $(GOPATH)/bin/linux_amd64/telehash-ping s3://lalala-assets/telehash-ping
	aws s3 cp --acl=public-read --region=us-east-1 $(GOPATH)/bin/linux_amd64/telehash-seed s3://lalala-assets/telehash-seed
	ssh root@95.85.6.236 make

seed-log:
	ssh root@95.85.6.236 tail -f /var/log/telehash.log

.PHONEY: build test test-profile examples seed-log seed-deploy
