# The detonation image of Agent Guard's dynamic tier (spec/sandbox.md §3).
#
# Build context: src/agentguard/sandbox (the harness and the sinkhole are copied from guest/).
# It is built once, on first use, and named after a hash of this file and the guest programs.
# Pin the base image by digest for a reproducible build:
#   docker build --build-arg BASE=python:3.12-slim-bookworm@sha256:<digest> ...
ARG BASE=python:3.12-slim-bookworm
FROM ${BASE}

# What is needed to run and watch a target: a tracer, a clock shim for trigger variation, the tools install
# scripts reach for, Node.js for JavaScript scripts and servers, and the MCP SDK for Python servers.
# npm is left out on purpose: the container has no network, so it could not install anything, and on this
# base it pulls in some 350 packages. A step that needs it is reported as not reached.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strace faketime iproute2 openssl ca-certificates curl wget git bash jq unzip netcat-openbsd nodejs procps \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "mcp>=1.2,<2" requests \
 && useradd --uid 1000 --user-group --no-create-home --home-dir /home/dev --shell /bin/bash dev

COPY guest/harness.py guest/sinkhole.py /opt/agentguard/

# The harness starts as root with a handful of capabilities, routes every address to the in-container
# sinkhole, and runs everything from the target as uid 1000 with no capabilities.
USER root
WORKDIR /work
ENTRYPOINT []
CMD ["python3", "/opt/agentguard/harness.py"]
