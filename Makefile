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

clean:
	go clean
	$(RM) -r vendor/*
	$(RM) $(BINARY)
	$(RM) certs/*
	$(RM) data.db
	$(RM) rootCA.*

.PHONY: all build fetch test clean
