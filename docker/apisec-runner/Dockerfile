FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Base system + apt-installable tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils less vim-tiny tree \
        ca-certificates curl wget \
        openssl \
        jq xmlstarlet xxd \
        dnsutils netcat-openbsd socat iputils-ping \
        postgresql-client default-mysql-client redis-tools \
        git unzip tar zip \
        python3 python3-pip python3-venv python3-dev \
        nodejs npm \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# yq (Mike Farah's, single Go binary)
RUN curl -fsSL https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
        -o /usr/local/bin/yq \
    && chmod +x /usr/local/bin/yq

# httpie via pip (newer than the apt package)
RUN pip3 install --no-cache-dir --break-system-packages httpie

# jwt-cli (Rust single binary) — pin version for reproducibility
RUN curl -fsSL https://github.com/mike-engel/jwt-cli/releases/download/6.2.0/jwt-linux.tar.gz \
        | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/jwt

# jwt_tool (ticarpi) — Python script with full attack toolkit
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && pip3 install --no-cache-dir --break-system-packages \
        -r /opt/jwt_tool/requirements.txt \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py

# ffuf (HTTP fuzzer)
RUN curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
        | tar -xz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf

# gobuster
RUN curl -fsSL https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
        | tar -xz -C /usr/local/bin/ gobuster \
    && chmod +x /usr/local/bin/gobuster

# kiterunner
RUN curl -fsSL https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz \
        | tar -xz -C /usr/local/bin/ kr \
    && chmod +x /usr/local/bin/kr

# Python exploit / crypto / fuzzing libraries
RUN pip3 install --no-cache-dir --break-system-packages \
        httpx requests aiohttp websockets \
        "pyjwt[crypto]" python-jose cryptography \
        beautifulsoup4 lxml \
        arjun sqlmap

# Compact API-focused wordlists from SecLists
RUN mkdir -p /usr/share/wordlists \
    && curl -fsSL -o /usr/share/wordlists/api-objects.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt \
    && curl -fsSL -o /usr/share/wordlists/api-actions.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/actions.txt \
    && curl -fsSL -o /usr/share/wordlists/common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    && curl -fsSL -o /usr/share/wordlists/raft-small-words.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt

# Sandbox layout
RUN mkdir -p /sandbox /workspace \
    && chmod 1777 /sandbox
COPY TOOLS.md /sandbox/TOOLS.md

WORKDIR /sandbox

# Container stays alive so the agent can `podman exec` repeatedly
CMD ["sleep", "infinity"]
