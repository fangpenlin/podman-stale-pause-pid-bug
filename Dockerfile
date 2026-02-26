# ---------- stage 1: build patched podman from source ----------
FROM registry.fedoraproject.org/fedora:41 AS builder

RUN dnf install -y \
    golang git make gcc \
    glib2-devel gpgme-devel device-mapper-devel \
    libseccomp-devel systemd-devel \
    btrfs-progs-devel shadow-utils-subid-devel \
    && dnf clean all

ARG PODMAN_VERSION=v5.7.0
RUN git clone --branch ${PODMAN_VERSION} --depth 1 \
    https://github.com/containers/podman.git /src/podman

COPY patches/ /patches/
RUN python3 /patches/add_debug_logging.py \
    /src/podman/pkg/rootless/rootless_linux.c \
    /src/podman/pkg/rootless/rootless_linux.go

RUN cd /src/podman && make podman

# ---------- stage 2: final image ----------
FROM quay.io/podman/stable:v5.7.0

USER root

COPY --from=builder /src/podman/bin/podman /usr/bin/podman
COPY --from=builder /usr/lib64/libsubid.so.4* /usr/lib64/

RUN useradd -m testuser && \
    printf '%s\n' \
      "root:1:65535" \
      "podman:1:999" \
      "podman:1001:64535" \
      "testuser:1:1000" \
      "testuser:1002:64534" \
      > /etc/subuid && \
    cp /etc/subuid /etc/subgid

RUN mkdir -p /home/testuser/.local/share/containers && \
    chown -R testuser:testuser /home/testuser

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER testuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["podman", "run", "--rm", "docker.io/library/hello-world"]
