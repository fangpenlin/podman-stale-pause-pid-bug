FROM quay.io/podman/stable:v5.7.0

USER root

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
