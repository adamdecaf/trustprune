FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# libnss3-tools provides certutil (required by the NSS store). Seed Chrome's
# Linux NSS DB under the container HOME so tests never touch a host store.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libnss3-tools && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.pki/nssdb && \
    certutil -N -d sql:/root/.pki/nssdb --empty-password && \
    for f in /etc/ssl/certs/*.pem; do \
      nick=$(basename "$f" .crt); nick=${nick%.pem}; \
      certutil -A -n "$nick" -t "CT,C,C" -i "$f" -d sql:/root/.pki/nssdb || true; \
    done && \
    test "$(certutil -L -d sql:/root/.pki/nssdb | wc -l)" -gt 20

COPY globalsign-whitelist.json /allowlist.json
COPY localcert.pem /localcert.pem

# trustprune and script.sh are bind-mounted at run.
CMD ["/bin/script.sh"]
