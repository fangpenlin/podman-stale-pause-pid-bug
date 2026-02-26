# Podman Stale Pause PID Bug

Reproducer for a [Podman bug where a stale `pause.pid` file pointing to a live (but unrelated) process causes unexpected behavior](https://github.com/containers/podman/issues/28157).

## Usage

Build the image:

```bash
docker build -t podman-stale-pause-pid-bug .
```

Run with Compose:

```bash
docker compose up
```
