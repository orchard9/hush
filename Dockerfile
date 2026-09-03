# hushd. Built amd64 IN-CLUSTER by Kaniko — never `docker build` locally, which
# on an Apple Silicon laptop produces an arm64 image the cluster cannot run.
#
# The build is HERMETIC: `-mod=vendor` with `GOPROXY=off` and `GOFLAGS=-mod=vendor`
# means no module download and no network. That is not an optimisation — it is
# required, because github.com/orchard9/go-chassis is a private module and the
# build container holds no git credential. `make vendor` is what moves versions.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Vendored, so this is the whole dependency graph: no go.sum verification step,
# no proxy, no cache warm-up.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Fail loudly if anything reaches for the network, rather than silently falling
# back to a proxy that will not be there in CI.
ENV GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0

# Tests run in the CI step, not here: a Kaniko layer that runs tests caches
# their result and stops re-running them. Keep the image build to building.
RUN go build -trimpath -ldflags="-s -w" -o /out/hushd ./cmd/hushd

# distroless static + nonroot: no shell, no package manager, no libc surface.
# hushd needs only TCP and the CA bundle distroless already carries.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /

COPY --from=build /out/hushd /hushd

# Numeric, not "nonroot": with a non-numeric USER the kubelet cannot verify
# runAsNonRoot and refuses to start the pod.
USER 65532:65532

# HTML templates are embedded in the binary (internal/web, go:embed), so there
# is no asset directory to mount, drift, or go missing at runtime.
EXPOSE 18500

# Exec form so SIGTERM reaches the process directly. The chassis's two-phase
# drain (readiness 503, wait, then shutdown) depends on receiving it, and the
# Deployment's terminationGracePeriodSeconds is sized to outlast that drain.
ENTRYPOINT ["/hushd"]
