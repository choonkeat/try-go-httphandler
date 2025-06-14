.PHONY: build run test clean

build:
	go build -o bin/app

run:
	go run . $(RUN_FLAGS)

test:
	go test ./...

clean:
	rm -rf bin/

dev: run

install:
	go mod tidy

.DEFAULT_GOAL := run
