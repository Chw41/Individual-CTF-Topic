FROM php:8.1-apache
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
WORKDIR /var/www/html
COPY index.php /var/www/html/index.php
COPY assets /var/www/html/assets/
COPY flag /flag
