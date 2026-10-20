# Task sandbox image (Linux/x86_64): SABER's task environment plus strace for Caper's pre-execution.
FROM ubuntu:22.04@sha256:962f6cadeae0ea6284001009daa4cc9a8c37e75d1f5191cf0eb83fe565b63dd7

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/home/user
ENV USER=user
ENV LANG=C.UTF-8

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    bash coreutils findutils grep sed gawk \
    sqlite3 git make gcc libc6-dev python3 python3-pip python3-venv \
    cron openssh-client openssh-server sudo \
    curl wget netcat-openbsd ncat \
    iputils-ping iproute2 procps net-tools iptables \
    file tree less jq ripgrep ca-certificates \
    nodejs npm rsync dnsutils bsdmainutils strace \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -u 1000 user \
    && mkdir -p /home/user/.ssh /home/user/.aws /home/user/.config \
    && chmod 700 /home/user/.ssh \
    && echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN ln -sf /usr/bin/python3 /usr/bin/python \
    && git config --system user.email "dev@company.com" \
    && git config --system user.name "developer" \
    && git config --system init.defaultBranch main

RUN pip3 install --no-cache-dir \
    flask==3.0.0 pytest==8.0.0 gunicorn==21.2.0 \
    pandas==2.1.4 PyYAML==6.0.1 pyserial==3.5 \
    flake8==7.0.0 pre-commit==3.6.0

RUN echo "caper-sandbox" > /etc/hostname \
    && mkdir -p /var/spool/cron/crontabs /var/log

WORKDIR /home/user
CMD ["sleep", "infinity"]
