NAME := torhoney

export GOPATH := $(PWD)

.PHONY: all install test fmt vet
all: 
	@go install $(NAME)

test fmt vet install:
	@go $@ $(NAME)
