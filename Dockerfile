FROM fedora:41

RUN dnf -y install podman fuse-overlayfs shadow-utils && dnf clean all

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY etc/subuid etc/subgid /etc-override/
COPY etc/containers/storage.conf /etc-override/containers/

ENTRYPOINT ["/entrypoint.sh"]
CMD ["podman", "run", "--rm", "docker.io/library/hello-world"]
