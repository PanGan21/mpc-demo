BINARY_NAME := mpc-demo
BUILD_DIR := bin
CMD_PATH := ./cmd/mpc-demo

GO := go
GOFLAGS :=

.DEFAULT_GOAL := help

.PHONY: build run fmt tidy clean

build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

run: ## Run the demo directly
	$(GO) run $(CMD_PATH)/main.go

fmt: ## Format all Go source files
	$(GO) fmt ./...

tidy: ## Tidy module dependencies
	$(GO) mod tidy

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
