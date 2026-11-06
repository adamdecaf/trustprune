# Gentoo stage3 already ships app-misc/ca-certificates (Debian-style layout
# per https://wiki.gentoo.org/wiki/Certificates). Skip OpenJDK: emerging it
# from source exceeds CI time; platform + certifi cover the Gentoo store path.
FROM gentoo/stage3:latest

RUN python3 -m venv /opt/trustprune-certifi && \
    /opt/trustprune-certifi/bin/pip install --no-cache-dir certifi

COPY globalsign-whitelist.json /allowlist.json
COPY us-whitelist.yaml /allowlist.yaml
COPY localcert.pem /localcert.pem

# trustprune and script.sh are bind-mounted at run so suite/certifi share this image.
CMD ["/bin/script.sh"]
