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

lint:
	@which goose || (echo First, install https://block.github.io/goose ; exit 1)
	goose run --text "Check that this codebase adheres to CODE.md. Output each rule with a prefix 'PASS ' or 'FAIL reason '" | tee lint.txt
	@grep 'FAIL reason' lint.txt && rm -f lint.txt && exit 1 || rm -f lint.txt

.DEFAULT_GOAL := run
