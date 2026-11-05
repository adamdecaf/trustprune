FROM rockylinux:9

RUN dnf install -y --allowerasing ca-certificates curl diffutils java-21-openjdk-devel python3 python3-pip python3-setuptools && \
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
