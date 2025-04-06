FROM php:8.2-apache

# Définition du répertoire de travail
WORKDIR /var/www/html

# Copie du code source de l'application dans le conteneur
COPY . /var/www/html

# Mise à jour et installation des dépendances nécessaires
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    zip unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install pdo pdo_mysql gd

# Activation de mod_rewrite (souvent utile pour les frameworks PHP comme Laravel)
RUN a2enmod rewrite

# Expose le port 80
EXPOSE 80

# cmd
CMD ["apache2-foreground"]
