FROM alpine:3.19 AS build

# Setup web certs
# TODO: actually install & run certbot?
COPY cert.tar.gz /cert.tar.gz
RUN mkdir /etc/letsencrypt && \
    cd /etc/letsencrypt && \
    tar xf /cert.tar.gz

# Install build deps
RUN apk update && apk upgrade && apk add \
    build-base     \
    libffi-dev     \
    python3-dev    \
    py3-pip        \
    clang          \
    linux-headers  \
    sqlite         \
    certbot        \
    git

# Install radius deps
COPY pip.deps /pip.deps
RUN python3 -m venv /radius-venv && \
    source /radius-venv/bin/activate && \
    pip install -r /pip.deps

COPY . /orbit
WORKDIR /orbit

# Setup email
RUN make -C pop3 clean all && \
    make -C smtp clean all && \
    EMAIL_DIR="$(./config.py email_dir)" && \
    mkdir -p "$EMAIL_DIR"/mail "$EMAIL_DIR"/logs && \
    chown -R mail:mail "$EMAIL_DIR"

# Setup orbit db
# TODO: use a volume so the db is persistent between builds
#       and remove this line from the dockerfile
RUN sqlite3 orbit.db ".read init-db.sql"

# Setup nginx
RUN mkdir -p /etc/nginx && \
    ./nginx_config.sh > /etc/nginx/nginx.conf


FROM alpine:3.19 AS orbit

RUN apk update && apk upgrade && apk add \
    python3        \
    s6             \
    s6-networking  \
    nginx          \
    nginx-mod-mail \
    sqlite         \
    netcat-openbsd \
    curl           \
    git

COPY --from=build /etc/nginx /etc/nginx
COPY --from=build /etc/letsencrypt /etc/letsencrypt
COPY --from=build /orbit /orbit
COPY --from=build /radius-venv /radius-venv

HEALTHCHECK CMD /orbit/docker/healthcheck.sh

CMD /orbit/docker/init.sh
