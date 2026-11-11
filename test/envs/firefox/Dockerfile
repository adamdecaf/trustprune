FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# libnss3-tools provides certutil (required by the NSS store). Seed a shared-DB
# Firefox profile under the container HOME so tests never touch a host store.
# Archive DNS blips fail apt-get update before Acquire::Retries applies.
RUN n=0; until apt-get -o Acquire::Retries=5 update; do \
      n=$((n + 1)); \
      if [ "$n" -ge 5 ]; then exit 1; fi; \
      sleep "$n"; \
    done && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates libnss3-tools && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.mozilla/firefox/docker.default && \
    certutil -N -d sql:/root/.mozilla/firefox/docker.default --empty-password && \
    for f in /etc/ssl/certs/*.pem; do \
      nick=$(basename "$f" .crt); nick=${nick%.pem}; \
      certutil -A -n "$nick" -t "CT,C,C" -i "$f" -d sql:/root/.mozilla/firefox/docker.default || true; \
    done && \
    test "$(certutil -L -d sql:/root/.mozilla/firefox/docker.default | wc -l)" -gt 20

COPY globalsign-whitelist.json /allowlist.json
COPY localcert.pem /localcert.pem

# trustprune and script.sh are bind-mounted at run.
CMD ["/bin/script.sh"]
