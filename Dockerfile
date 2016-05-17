FROM golang:1.6.0-wheezy

ENV VERSION 1.11.1

RUN apt-get  update && apt-get install -y git auditd

COPY . $GOPATH/src/github.com/diogomonica/actuary
WORKDIR $GOPATH/src/github.com/diogomonica/actuary
RUN go get github.com/tools/godep
RUN $GOPATH/bin/godep restore
RUN go install github.com/diogomonica/actuary/cmd/actuary 

ENTRYPOINT ["/go/bin/actuary"]
