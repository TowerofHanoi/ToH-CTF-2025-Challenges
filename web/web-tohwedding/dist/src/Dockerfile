# Use the official PHP image with Apache
FROM php:8.1-apache

# Set working directory
WORKDIR /var/www/html

# Copy application source code to the container
COPY . /var/www/html

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html

RUN apt-get update && apt-get install -y openssl

# Expose port 80
EXPOSE 80

# Working as a non-root user
RUN usermod -u 1000 www-data

# Entrypoint script to initialize secret
RUN mv ./entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# Start Apache server
CMD ["apache2-foreground"]