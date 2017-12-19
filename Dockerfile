FROM       golang:1.9 as build
MAINTAINER Quentin Machu <quentin.machu@coreos.com>
ENV        GOPATH /go
WORKDIR    /build
ADD        . /go/src/github.com/coreos/kapprover
RUN        go get -d github.com/coreos/kapprover/cmd/kapprover
RUN        CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' github.com/coreos/kapprover/cmd/kapprover

FROM scratch
COPY --from=build /build/kapprover /go/bin/kapprover
CMD ["/go/bin/kapprover"]
