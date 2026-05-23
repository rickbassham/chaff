.DEFAULT_GOAL := help

.PHONY: help install build test typecheck lint format format-check audit

help: ## Show this help message
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Run 'make <target>' to execute a target."

install: ## Install dependencies with frozen lockfile
	pnpm install --frozen-lockfile

build: ## Build the project (TypeScript -> dist/)
	pnpm build

test: ## Run the full test suite
	pnpm test

typecheck: ## Run TypeScript type checker (tsc --noEmit)
	pnpm typecheck

lint: ## Run ESLint
	pnpm lint

format: ## Format code with Prettier (writes)
	pnpm format

format-check: ## Check formatting without writing
	pnpm format:check

audit: ## Run security audit at high level
	pnpm audit --audit-level=high
