# ==========================
# Builder stage
# ==========================
FROM quay.io/centos/centos:stream9 as builder

ARG TARGETARCH

# Install Go and required tools
RUN dnf install -y make git && dnf clean all
ENV GO_VERSION=1.23.9

RUN curl -LO https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

WORKDIR /workspace

# Copy source
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -o bin/ipu-rhel-iso-builder.${TARGETARCH} .

# ==========================
# Runtime stage
# ==========================
FROM quay.io/centos/centos:stream9

WORKDIR /root

ARG TARGETARCH

# Install ISO tooling
RUN dnf install -y lorax xorriso skopeo && dnf clean all

# Copy built binary
COPY --from=builder /workspace/bin/ipu-rhel-iso-builder.${TARGETARCH} /usr/local/bin/ipu-rhel-iso-builder

# Make sure it's executable
RUN chmod +x /usr/local/bin/ipu-rhel-iso-builder

ENTRYPOINT ["/usr/local/bin/ipu-rhel-iso-builder"]
