GOPATH = $(CURDIR)/../vendor:$(CURDIR)

all: build

build:
	go fmt *.go
	go build -o test *.go

clean:
	$(RM) test

.PHONY: all build clean
