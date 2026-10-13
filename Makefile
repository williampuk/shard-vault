.PHONY: build test run integration fuzz vet

build:
	go build -mod=vendor -buildvcs=false -trimpath -o shardvault ./cmd/shardvault

test:
	go test -mod=vendor -race ./...

vet:
	go vet -mod=vendor ./...

run:
	go run -mod=vendor -buildvcs=false ./cmd/shardvault

integration: build
	python3 tests/pty_smoke.py ./shardvault

fuzz:
	go test -mod=vendor ./internal/share -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=15s -parallel=2
	go test -mod=vendor ./internal/share -run '^$$' -fuzz '^FuzzUnpack$$' -fuzztime=15s -parallel=2
	go test -mod=vendor ./internal/share -run '^$$' -fuzz '^FuzzRecover$$' -fuzztime=15s -parallel=2
