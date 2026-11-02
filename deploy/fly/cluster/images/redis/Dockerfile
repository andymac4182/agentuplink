# syntax=docker/dockerfile:1
# Repository-root context; this does not change the historical Redis image.
FROM redis:8.4.0-alpine@sha256:4eec4565e45aa0b3966554c866bc73211e281b0b3d89fe9a33c982e6faca809d
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
COPY deploy/fly/redis/notices/ /usr/local/share/licenses/agentuplink-redis/
RUN test "${#VCS_REF}" -eq 40 \
 && case "$VCS_REF" in *[!0-9a-f]*) exit 1;; esac \
 && test "$REDIS_DOWNLOAD_SHA" = b947d9015622669b5bee8ec954f658b3278d42dbefae23a92d9b7704bfe143f9 \
 && cd /usr/local/share/licenses/agentuplink-redis && sha256sum -c SHA256SUMS \
 && apk add --no-cache python3 \
 && python3 -I -c 'import base64, binascii, hashlib, json, os, pathlib, pwd, re, stat, sys, tomllib, uuid' \
 && install -d -m 0700 -o redis -g redis /var/lib/agentuplink-redis /var/lib/agentuplink-redis/secrets /data/redis \
 && install -d /usr/local/share/agentuplink-runtime-provenance \
 && apk info -vv > /usr/local/share/agentuplink-runtime-provenance/os-packages.txt
COPY deploy/fly/cluster/images/entrypoint.py /usr/local/libexec/agentuplink-cluster-entrypoint.py
COPY deploy/fly/cluster/images/PROVENANCE.md /usr/local/share/agentuplink-runtime-provenance/README.md
USER redis:redis
WORKDIR /var/lib/agentuplink-redis
EXPOSE 6379
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/python3", "-I", "/usr/local/libexec/agentuplink-cluster-entrypoint.py", "redis"]
CMD ["serve"]
