# Actaeon container: non-root, no build tools in the final image.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE config.example.yaml ./
COPY actaeon ./actaeon
RUN pip install --no-cache-dir build && python -m build --wheel -o /dist .

FROM python:3.12-slim
ARG EXTRAS="all"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ACTAEON_HOME=/data ACTAEON_BIND_HOST=0.0.0.0 ACTAEON_BIND_PORT=8601
COPY --from=build /dist /dist
RUN pip install --no-cache-dir "$(ls /dist/*.whl)[${EXTRAS}]" && rm -rf /dist \
    && groupadd -g 10001 actaeon && useradd -u 10001 -g 10001 -d /data -s /usr/sbin/nologin actaeon \
    && mkdir -p /data && chown actaeon:actaeon /data
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8601
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8601/healthz',timeout=4).status==200 else 1)"
# First start: writes /data/config.yaml and /data/.env if they are missing, then serves.
CMD ["sh", "-c", "[ -f /data/config.yaml ] || actaeon init; exec actaeon serve"]
