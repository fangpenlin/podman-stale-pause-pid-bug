FROM quay.io/podman/stable

USER root

RUN useradd -m testuser && \
    echo "testuser:100000:65536" >> /etc/subuid && \
    echo "testuser:100000:65536" >> /etc/subgid

RUN mkdir -p /home/testuser/.local/share/containers && \
    chown -R testuser:testuser /home/testuser

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER testuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["podman", "run", "--rm", "docker.io/library/hello-world"]
