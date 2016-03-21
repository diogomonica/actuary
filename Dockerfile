FROM golang:1.6.0-wheezy

ENV VERSION 1.10.2

RUN apt-get  update && apt-get install -y git auditd

COPY . $GOPATH/src/github.com/diogomonica/actuary
WORKDIR $GOPATH/src/github.com/diogomonica/actuary
RUN go get -u github.com/tools/godep
RUN $GOPATH/bin/godep go install
RUN go install github.com/diogomonica/actuary 

ENTRYPOINT ["/go/bin/actuary"]
