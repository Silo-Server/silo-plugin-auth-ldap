.PHONY: build test test-directories test-lab vet lint clean build-all

BINARY=plugin
PLATFORMS=linux/amd64 linux/arm64 darwin/arm64
VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
LDFLAGS=-s -w -X main.version=$(VERSION)

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

# Tests against lldap and OpenLDAP in Docker, as CI runs them. Needs Docker
# and openssl; see scripts/directory-containers.sh for settings.
test-directories:
	@env_file=$$(scripts/directory-containers.sh up) || { scripts/directory-containers.sh down; exit 1; }; \
	set -a; . "$$env_file"; set +a; \
	go test -count=1 -run TestContainerDirectories -v ./ldapauth/; \
	status=$$?; scripts/directory-containers.sh down; exit $$status

# Live tests against the maintainers' SSO lab, which adds the authentik LDAP
# outpost and Kanidm. Needs SSO_LAB_ENV (credentials file) and SSO_LAB_CA (CA
# PEM); see ldapauth/lab_test.go.
test-lab:
	SSO_LAB=1 go test -count=1 -run TestLabDirectories -v ./ldapauth/

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BINARY) dist

build-all:
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%%/*} GOARCH=$${platform##*/} CGO_ENABLED=0 \
		go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-$${platform%%/*}-$${platform##*/} . || exit 1; \
	done
