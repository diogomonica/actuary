FROM golang:1.8.3

ENV VERSION 17.06.0
ENV GOBIN=$GOPATH/bin

RUN apt-get  update && apt-get install -y git auditd

COPY . $GOPATH/src/github.com/diogomonica/actuary
WORKDIR $GOPATH/src/github.com/diogomonica/actuary
RUN go install github.com/diogomonica/actuary/cmd/actuary

ENTRYPOINT ["/go/bin/actuary"]