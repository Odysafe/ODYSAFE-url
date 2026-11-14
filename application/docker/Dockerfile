# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962
FROM ${PYTHON_IMAGE} AS app-dependencies

ARG ODYSAFE_UID=1000
ARG ODYSAFE_GID=1000
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    ODYSAFE_DATA_DIR=/data HOME=/home/odysafe PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN groupadd --gid "${ODYSAFE_GID}" odysafe \
 && useradd --uid "${ODYSAFE_UID}" --gid "${ODYSAFE_GID}" --create-home odysafe
WORKDIR /opt/odysafe
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/*
COPY repo/har2tree/ repo/har2tree/
COPY pyproject.toml constraints-app.txt constraints-capture.txt ./
COPY THIRD_PARTY_NOTICES.md ./
COPY repo/har2tree/LICENSE /usr/share/licenses/odysafe-url/har2tree-LICENSE
# Dependency layers depend only on manifests and vendored libraries, so a web
# fix does not reinstall Chromium, Xpra or the Python dependency tree.
RUN python -m pip install --upgrade 'pip==25.2'
RUN python - <<'PYDEPS'
import subprocess
import sys
import tomllib
from pathlib import Path
requirements = tomllib.loads(Path("pyproject.toml").read_text())["project"]["dependencies"]
subprocess.check_call([sys.executable, "-m", "pip", "install", "--constraint", "constraints-app.txt", *requirements])
PYDEPS
RUN mkdir -p /data/scans /database /backups /tmp/odysafe \
 && chown -R odysafe:odysafe /data /database /backups /tmp/odysafe \
 && chmod 0700 /database \
 && rm -rf /opt/odysafe/repo/har2tree
USER odysafe

FROM app-dependencies AS browser-dependencies
USER root
COPY repo/PlaywrightCapture/ repo/PlaywrightCapture/
COPY repo/PlaywrightCapture/LICENSE /usr/share/licenses/odysafe-url/PlaywrightCapture-LICENSE
RUN python -m pip install --constraint constraints-capture.txt 'PlaywrightCapture @ file:repo/PlaywrightCapture' \
 && python -m playwright install --with-deps --no-shell chromium \
 && rm -rf /var/lib/apt/lists/* /root/.cache /opt/odysafe/repo/PlaywrightCapture
USER odysafe
ENTRYPOINT ["python", "-m", "app.sandbox.runner"]

FROM browser-dependencies AS interactive-dependencies
USER root
ARG XPRA_KEY_FINGERPRINT=B4993B57323148E37977E5D873254CAD17978FAF
COPY docker/interactive/xpra.sources /tmp/xpra.sources
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gnupg wget \
 && wget -qO /usr/share/keyrings/xpra.asc https://xpra.org/xpra.asc \
 && gpg --show-keys --with-colons /usr/share/keyrings/xpra.asc | grep -q "fpr:::::::::${XPRA_KEY_FINGERPRINT}:" \
 && mv /tmp/xpra.sources /etc/apt/sources.list.d/xpra.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends xpra xpra-html5 xpra-x11 xauth \
 && xpra --version \
 && dpkg-query -W xpra xpra-html5 xpra-x11 \
 && rm -rf /var/lib/apt/lists/*
USER odysafe

FROM app-dependencies AS app
COPY app/ app/
COPY config/ config/
COPY rules/ rules/
USER root
RUN python -m pip install --no-deps . \
 && rm -rf /opt/odysafe/build /opt/odysafe/odysafe_url.egg-info \
 && rm -rf /tmp/* /run/* /root/.cache /home/odysafe/.cache
USER odysafe
CMD ["sleep", "infinity"]

FROM browser-dependencies AS browser
COPY --from=app /opt/odysafe/ /opt/odysafe/
USER root
RUN python -m pip install --no-deps . \
 && rm -rf /opt/odysafe/build /opt/odysafe/odysafe_url.egg-info \
 && rm -rf /tmp/* /run/* /root/.cache /home/odysafe/.cache
USER odysafe
ENTRYPOINT ["python", "-m", "app.sandbox.runner"]

FROM interactive-dependencies AS interactive
COPY --from=app /opt/odysafe/ /opt/odysafe/
USER root
RUN python -m pip install --no-deps . \
 && rm -rf /opt/odysafe/build /opt/odysafe/odysafe_url.egg-info \
 && rm -rf /tmp/* /run/* /root/.cache /home/odysafe/.cache
COPY docker/interactive/xpra-reconnect-auth.js /usr/share/xpra/www/js/odysafe-reconnect-auth.js
RUN sed -i '/odysafe-reconnect-auth/d; /src="js\/Client.js"/a\    <script type="text/javascript" src="js/odysafe-reconnect-auth.js"></script>' /usr/share/xpra/www/index.html \
 && rm -f /usr/share/xpra/www/index.html.br /usr/share/xpra/www/index.html.gz
COPY --chmod=755 docker/interactive/entrypoint.sh /usr/local/bin/odysafe-interactive
USER odysafe
EXPOSE 14500
ENTRYPOINT ["/usr/local/bin/odysafe-interactive"]

FROM ${PYTHON_IMAGE} AS fixture
ARG ODYSAFE_UID=1000
ARG ODYSAFE_GID=1000
RUN groupadd --gid "${ODYSAFE_GID}" fixture \
 && useradd --uid "${ODYSAFE_UID}" --gid "${ODYSAFE_GID}" --no-create-home fixture
WORKDIR /srv/fixtures
COPY tests/fixtures/ ./
COPY docker/fixture/server.py /srv/server.py
USER fixture
CMD ["python", "/srv/server.py"]

FROM ${PYTHON_IMAGE} AS xpra-gateway
ARG ODYSAFE_UID=1000
ARG ODYSAFE_GID=1000
RUN groupadd --gid "${ODYSAFE_GID}" gateway \
 && useradd --uid "${ODYSAFE_UID}" --gid "${ODYSAFE_GID}" --no-create-home gateway \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY docker/interactive/gateway.py /srv/gateway.py
COPY docker/interactive/certificate.py /srv/certificate.py
USER gateway
CMD ["python", "/srv/gateway.py"]

FROM debian:trixie-slim AS internet-proxy
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/squid /var/spool/squid \
 && chown -R proxy:proxy /run/squid /var/spool/squid
COPY docker/internet-proxy/squid.conf /etc/squid/squid.conf
RUN squid -k parse -f /etc/squid/squid.conf
USER proxy
EXPOSE 3128
CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
