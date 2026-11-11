FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# apt-get update can exit 0 after a transient DNS failure; --error-on=any makes the retry loop run.
RUN n=0; until apt-get -o Acquire::Retries=5 --error-on=any update; do \
      n=$((n + 1)); \
      if [ "$n" -ge 5 ]; then exit 1; fi; \
      sleep "$n"; \
    done && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates curl openjdk-21-jdk-headless python3 python3-venv python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sfn "$(dirname "$(dirname "$(readlink -f "$(which javac)")")")" /usr/lib/jvm/java-home && \
    python3 -m venv /opt/trustprune-certifi && \
    /opt/trustprune-certifi/bin/pip install --no-cache-dir certifi
ENV JAVA_HOME=/usr/lib/jvm/java-home
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY globalsign-whitelist.json /allowlist.json
COPY us-whitelist.yaml /allowlist.yaml

COPY Download.java /Download.java
RUN javac /Download.java

COPY localcert.pem /localcert.pem

# trustprune and script.sh are bind-mounted at run so suite/java share this image.
CMD ["/bin/script.sh"]
