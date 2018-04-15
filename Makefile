export GOPATH = $(CURDIR)/vendor:$(CURDIR)/cmd

fetch:
	go get github.com/mattn/go-sqlite3

install:
	go install github.com/mattn/go-sqlite3
