FROM php:8.1-apache

RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav sudo && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

COPY www/ /var/www/html/
COPY sigs/ /opt/sigs/
COPY flag /flag
COPY sudoers/oracle /etc/sudoers.d/oracle

RUN useradd -m -u 10001 appuser && \
    mkdir -p /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html && \
    chmod 644 /opt/sigs/custom.ndb && \
    chmod 0440 /etc/sudoers.d/oracle && \
    visudo -c && \
    chown root:root /flag && \
    chmod 600 /flag

EXPOSE 80
