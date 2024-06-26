ARG GO_VERSION

FROM golang:${GO_VERSION}-alpine AS build

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux

WORKDIR /build

COPY go.mod go.sum *.go LICENSE ./
COPY syscalls/ ./syscalls/
COPY generate/ ./generate/
COPY interceptor/ ./interceptor/

RUN go generate ./... && go test ./... && go build -o main .

FROM alpine:3.18.2

WORKDIR /dist

COPY --from=build /build/main /build/LICENSE ./

ENTRYPOINT ["/dist/main"]

