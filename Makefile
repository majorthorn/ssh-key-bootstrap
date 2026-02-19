.PHONY: security

GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

security:
	$(GOBIN)/govulncheck ./...
	$(GOBIN)/gosec ./...
	$(GOBIN)/staticcheck ./...
