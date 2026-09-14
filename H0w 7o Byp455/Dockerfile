FROM php:8.1-apache

RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav sudo && \
# HANDOUT-STRIP-BEGIN
    apt-get install -y --no-install-recommends gcc && \
# HANDOUT-STRIP-END
    rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

COPY www/ /var/www/html/
COPY sigs/ /opt/sigs/
COPY flag /flag
COPY sudoers/oracle /etc/sudoers.d/oracle
# HANDOUT-STRIP-BEGIN
COPY chw/chw.c /tmp/chw.c
# HANDOUT-STRIP-END

RUN useradd -m -u 10001 appuser && \
    mkdir -p /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html && \
    chmod 644 /opt/sigs/custom.ndb && \
    chmod 0440 /etc/sudoers.d/oracle && \
    visudo -c && \
# HANDOUT-STRIP-BEGIN
    mkdir -p /var/log/chw && \
    gcc -O0 -o /usr/local/bin/chw /tmp/chw.c && \
    rm /tmp/chw.c && \
    chown root:appuser /usr/local/bin/chw && \
    chmod 4750 /usr/local/bin/chw && \
    apt-get purge -y gcc && apt-get autoremove -y && \
# HANDOUT-STRIP-END
    chown root:root /flag && \
    chmod 600 /flag

EXPOSE 80
