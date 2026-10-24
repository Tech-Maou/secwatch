# secwatch for generic Linux hosts: web UI + scanner (scheduler loop) in one image.
# Build from the repository root:  docker build -f docker/Dockerfile -t secwatch .
ARG TRIVY_VERSION=0.72.0
FROM docker.io/aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM docker.io/library/python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --user-group --home-dir /var/lib/secwatch --shell /usr/sbin/nologin secwatch

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
# Apache-2.0 §4: ship Trivy's licence and NOTICE with the binary
COPY docker/licenses/trivy/ /usr/share/licenses/trivy/
COPY THIRD_PARTY.md /usr/share/licenses/secwatch/THIRD_PARTY.md

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY secwatch ./secwatch
RUN pip install --no-cache-dir . && rm -rf /src

COPY docker/entrypoint.sh /usr/local/bin/secwatch-entrypoint
RUN chmod 0755 /usr/local/bin/secwatch-entrypoint

# Container-specific settings are locked (shown read-only in the UI):
#  - the host root file system is mounted read-only at /host for the `os` collector
#  - the web server listens on all interfaces *inside* the container (publish the port on 127.0.0.1)
ENV SECWATCH_STATE_DIR=/var/lib/secwatch \
    SECWATCH__collectors__os__root=/host \
    SECWATCH__web__listen=0.0.0.0 \
    SECWATCH__collectors__nix__enabled=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/var/lib/secwatch"]
EXPOSE 8478
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8478/healthz', timeout=4)" || exit 1
ENTRYPOINT ["/usr/local/bin/secwatch-entrypoint"]
