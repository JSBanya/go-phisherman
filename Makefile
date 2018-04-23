<<<<<<< HEAD
BINARY=phisherman
GOPATH=$(CURDIR)/vendor/:$(CURDIR)/cmd/

all: build

build:
	go fmt $(CURDIR)/cmd/*.go
	go build -o $(BINARY) $(CURDIR)/cmd/*.go

fetch:
	go get github.com/glaslos/ssdeep

test:
	go test

clean:
	go clean
	rm -rf vendor/*
	rm -f $(BINARY)

.PHONY: all build fetch test clean
=======
export GOPATH = $(CURDIR)/vendor:$(CURDIR)/cmd

fetch:
	go get github.com/mattn/go-sqlite3
	go get github.com/glaslos/ssdeep

install:
	go install github.com/mattn/go-sqlite3
>>>>>>> 9ecf05f44803d0764f681d694190db21ebffe6fc
