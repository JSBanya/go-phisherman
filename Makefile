BINARY=phisherman
export GOPATH=$(CURDIR)/vendor/:$(CURDIR)/cmd/

all: build

build:
	go fmt $(CURDIR)/cmd/*.go
	go build -o $(BINARY) $(CURDIR)/cmd/*.go

fetch:
	go get github.com/mattn/go-sqlite3
	go get github.com/glaslos/ssdeep
	go get github.com/anthonynsimon/bild/effect
	go get github.com/anthonynsimon/bild/transform
	go get github.com/azr/phash

install:
	go install github.com/mattn/go-sqlite3

test:
	go test

clean:
	go clean
	rm -rf vendor/*
	rm -f $(BINARY)

.PHONY: all build fetch test clean
