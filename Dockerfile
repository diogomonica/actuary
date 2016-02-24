FROM golang:alpine

RUN apk add --update git


COPY . $GOPATH/src/github.com/diogomonica/actuary
WORKDIR $GOPATH/src/github.com/diogomonica/actuary
RUN go get -v ./...
RUN go install github.com/diogomonica/actuary

ENTRYPOINT ["/go/bin/actuary"]