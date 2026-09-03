.DEFAULT_GOAL := help
.PHONY: help fmt vet test test-redis build run dev dev-stop smoke vendor verify ci \
	mcp mcp-install release deploy-manifests deploy-status logs alerts-check

# Local development Redis. A real server, not a mock: the one-time guarantee
# rests on GETDEL being atomic, and a fake cannot prove that.
DEV_REDIS_PORT ?= 6389
DEV_REDIS_URL  ?= redis://127.0.0.1:$(DEV_REDIS_PORT)/5
HUSH_PORT      ?= 18500
BASE           ?= http://127.0.0.1:$(HUSH_PORT)

# The public deployment. `hushd` runs one replica in the `projects` namespace.
KUBECONFIG_FILE ?= $(HOME)/.kube/orchard9-k3sf.yaml
NS              ?= projects
HOST            ?= hush.threesix.ai

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

fmt: ## Format everything outside vendor/
	@gofmt -w ./cmd ./internal

vet: ## go vet
	@go vet ./...

test: ## Unit tests. No Redis, no network, no container.
	@go test ./...

test-redis: ## Run the store contract suite against a REAL Redis as well
	@$(MAKE) --no-print-directory dev-redis
	@HUSH_TEST_REDIS_URL=$(DEV_REDIS_URL) go test ./internal/store/... -count=1

build: ## Build both binaries into .build/
	@mkdir -p .build
	@go build -o .build/hushd ./cmd/hushd
	@go build -o .build/hush-mcp ./cmd/hush-mcp

# `vendor` is not a convenience: github.com/orchard9/go-chassis is a PRIVATE
# module, so neither the Woodpecker test step nor the in-cluster Kaniko build
# can fetch it. Vendoring makes both hermetic — they build with -mod=vendor and
# no network and no credential. This target is the only way dep versions move.
vendor: ## Refresh vendor/ after a dependency change
	@GOPRIVATE=github.com/orchard9 go mod tidy
	@GOPRIVATE=github.com/orchard9 go mod vendor
	@go build -mod=vendor ./... && echo "vendor/ builds hermetically"

verify: ## Prove the vendored tree builds with no network, exactly as CI does
	@GOFLAGS=-mod=vendor GOPROXY=off go build ./... \
	  && GOFLAGS=-mod=vendor GOPROXY=off go test ./... >/dev/null \
	  && echo "hermetic build OK (GOPROXY=off, -mod=vendor)"

ci: fmt vet test verify ## Everything the pipeline runs

dev-redis:
	@redis-cli -p $(DEV_REDIS_PORT) ping >/dev/null 2>&1 || { \
	  echo "starting redis on :$(DEV_REDIS_PORT)"; \
	  redis-server --port $(DEV_REDIS_PORT) --daemonize yes --save '' --appendonly no; \
	  for i in $$(seq 1 30); do redis-cli -p $(DEV_REDIS_PORT) ping >/dev/null 2>&1 && break; sleep 0.2; done; }
	@redis-cli -p $(DEV_REDIS_PORT) ping | sed 's/^/redis: /'

dev: dev-redis build ## Run hushd locally against a local Redis
	@echo "hushd on $(BASE) — open it in a browser"
	@APP_ENV=dev REDIS_URL=$(DEV_REDIS_URL) HUSH_PORT=$(HUSH_PORT) .build/hushd

dev-stop: ## Stop the local Redis
	@redis-cli -p $(DEV_REDIS_PORT) shutdown nosave 2>/dev/null || true
	@echo "stopped"

smoke: ## Full create -> reveal -> gone against a locally running hushd
	@BASE=$(BASE) ./scripts/smoke.sh

mcp: ## Build and install the MCP server, then register it with omp
	@$(MAKE) --no-print-directory mcp-install

mcp-install:
	@./scripts/install-mcp.sh

deploy-manifests: ## Apply the k8s manifests (do this BEFORE the first push)
	@KUBECONFIG=$(KUBECONFIG_FILE) kubectl apply -f deployments/k8s/hush.yaml

deploy-status: ## Rollout, pods, ingress and certificate
	@KUBECONFIG=$(KUBECONFIG_FILE) kubectl -n $(NS) rollout status deployment/hush --timeout=90s
	@KUBECONFIG=$(KUBECONFIG_FILE) kubectl -n $(NS) get pod,svc,ingress -l app=hush
	@KUBECONFIG=$(KUBECONFIG_FILE) kubectl -n $(NS) get certificate hush-tls 2>/dev/null || true

logs: ## Tail hush's structured logs out of VictoriaLogs
	@./scripts/logs.sh

alerts-check: ## Confirm vmalert has loaded hush's rules
	@./scripts/alerts-check.sh

release: ## Build this commit in-cluster and roll it out, then smoke it. Needs no CI credential.
	@./scripts/release.sh
