FROM fedora:latest

RUN dnf install -y ca-certificates curl diffutils python3 python3-pip python3-setuptools && \
    (dnf install -y java-21-openjdk-devel || dnf install -y java-25-openjdk-devel || dnf install -y java-latest-openjdk-devel) && \
    dnf clean all && \
    ln -sfn "$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")" /usr/lib/jvm/java-home && \
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
