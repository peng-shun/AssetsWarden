.PHONY: generate build install run clean

generate:
	cd internal/ebpf/bpf && GOPROXY=https://goproxy.cn,direct go generate ./...

build: generate
	go build -o bin/assetwarden ./cmd/assetwarden

install: build
	sudo cp bin/assetwarden /usr/local/bin/

run: build
	sudo ./bin/assetwarden --config configs/default.yaml

clean:
	rm -f bin/assetwarden
	rm -f internal/ebpf/bpf/warden_bpf*
