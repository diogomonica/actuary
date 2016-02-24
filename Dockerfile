FROM golang:alpine

ENV VERSION 1.10.2

RUN apk add --update git

COPY . $GOPATH/src/github.com/diogomonica/actuary
WORKDIR $GOPATH/src/github.com/diogomonica/actuary
RUN go get ./...
RUN go install github.com/diogomonica/actuary

ENTRYPOINT ["/go/bin/actuary"]