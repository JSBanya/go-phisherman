export GOPATH = $(CURDIR)/vendor:$(CURDIR)/cmd

fetch:
	go get github.com/mattn/go-sqlite3
	go get github.com/glaslos/ssdeep

install:
	go install github.com/mattn/go-sqlite3
