FROM ubuntu

# setup go
RUN apt-get update -y
RUN apt-get install git subversion mercurial bzr curl graphviz -y
RUN curl -o /tmp/go1.3.3.linux-amd64.tar.gz https://storage.googleapis.com/golang/go1.3.3.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.3.3.linux-amd64.tar.gz
RUN rm /tmp/go1.3.3.linux-amd64.tar.gz
RUN mkdir /go
ENV PATH $PATH:/usr/local/go/bin
ENV PATH $PATH:/go/bin
ENV GOPATH /go

# build telehash
COPY . /go/src/github.com/telehash/gogotelehash
WORKDIR /go/src/github.com/telehash/gogotelehash
RUN go get -v ./...

# test telehash
# RUN go test -v ./...

ENV TH_TRACER on
