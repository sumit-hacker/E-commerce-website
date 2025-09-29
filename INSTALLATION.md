# E-Commerce Authentication System - Installation Guide

## System Requirements

### Minimum Requirements
- **PHP**: 7.4 or higher (8.0+ recommended)
- **MySQL**: 5.7 or higher (8.0+ recommended)
- **Web Server**: Apache 2.4+ or Nginx 1.18+
- **SSL Certificate**: Required for production (Let's Encrypt recommended)
- **Memory**: 512MB RAM minimum (1GB+ recommended)
- **Storage**: 100MB disk space minimum

### PHP Extensions Required
```bash
# Check if extensions are installed
php -m | grep -E "(pdo|pdo_mysql|openssl|mbstring|json|session|filter|hash)"
```

Required extensions:
- `pdo`
- `pdo_mysql`
- `openssl`
- `mbstring`
- `json`
- `session`
- `filter`
- `hash`

## Installation Steps

### 1. Database Setup

#### Create Database
```sql
-- Connect to MySQL as root
mysql -u root -p

-- Create database
CREATE DATABASE ecommerce_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create database user (recommended)
CREATE USER 'ecommerce_user'@'localhost' IDENTIFIED BY 'your_secure_password_here';
GRANT ALL PRIVILEGES ON ecommerce_auth.* TO 'ecommerce_user'@'localhost';
FLUSH PRIVILEGES;
```

#### Import Database Schema
```bash
# Import the database schema
mysql -u ecommerce_user -p ecommerce_auth < database/schema.sql

# Verify tables were created
mysql -u ecommerce_user -p ecommerce_auth -e "SHOW TABLES;"
```

### 2. File Permissions

Set proper file permissions for security:

```bash
# Navigate to project directory
cd /path/to/E-commerce-website

# Set directory permissions
find auth/ -type d -exec chmod 755 {} \;

# Set file permissions
find auth/ -type f -exec chmod 644 {} \;

# Make sure web server can read files
chown -R www-data:www-data auth/
# OR for CentOS/RHEL:
# chown -R apache:apache auth/
```

### 3. Configuration

#### Database Configuration
Copy and configure the database settings:

```bash
# Copy example config (if you create one)
cp auth/config/database.example.php auth/config/database.php
```

Edit `auth/config/database.php`:
```php
// Update these constants with your database credentials
private const DB_HOST = 'localhost';
private const DB_NAME = 'ecommerce_auth';
private const DB_USER = 'ecommerce_user';
private const DB_PASS = 'your_secure_password_here';
```

#### Email Configuration
Configure SMTP settings in `auth/config/email.php`:

**For SendGrid:**
```php
private const SMTP_HOST = 'smtp.sendgrid.net';
private const SMTP_PORT = 587;
private const SMTP_USERNAME = 'apikey';
private const SMTP_PASSWORD = 'your-sendgrid-api-key';
```

**For Gmail (App Passwords):**
```php
private const SMTP_HOST = 'smtp.gmail.com';
private const SMTP_PORT = 587;
private const SMTP_USERNAME = 'your-email@gmail.com';
private const SMTP_PASSWORD = 'your-app-password';
```

**For Mailgun:**
```php
private const SMTP_HOST = 'smtp.mailgun.org';
private const SMTP_PORT = 587;
private const SMTP_USERNAME = 'postmaster@your-domain.mailgun.org';
private const SMTP_PASSWORD = 'your-mailgun-password';
```

#### Update Email Settings
Edit sender information in `auth/config/email.php`:
```php
private const FROM_EMAIL = 'noreply@yourdomain.com';
private const FROM_NAME = 'Your E-Commerce Store';
private const REPLY_TO_EMAIL = 'support@yourdomain.com';
```

### 4. Web Server Configuration

#### Apache (.htaccess)
Create `.htaccess` file in the `auth/` directory:
```apache
# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"

# HTTPS enforcement (uncomment for production)
# RewriteEngine On
# RewriteCond %{HTTPS} off
# RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Hide sensitive files
<Files "*.md">
    Require all denied
</Files>

<Files "composer.*">
    Require all denied
</Files>

# Prevent access to config files directly
<Files "database.php">
    Require all denied
</Files>

<Files "email.php">
    Require all denied
</Files>

<Files "security.php">
    Require all denied
</Files>
```

#### Nginx Configuration
Add to your Nginx server block:
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    # SSL configuration (use Let's Encrypt)
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    root /path/to/E-commerce-website;
    index index.php index.html;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
    
    # PHP configuration
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to sensitive files
    location ~* \.(md|txt|log)$ {
        deny all;
    }
    
    location ~ ^/auth/config/ {
        deny all;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 5. SSL Certificate Setup

#### Using Let's Encrypt (Recommended)
```bash
# Install Certbot
sudo apt update
sudo apt install certbot

# For Apache
sudo certbot --apache -d yourdomain.com

# For Nginx
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
sudo crontab -e
# Add this line:
# 0 12 * * * /usr/bin/certbot renew --quiet
```

### 6. Testing the Installation

#### Test Database Connection
Create a test file `test-db.php`:
```php
<?php
define('AUTH_SYSTEM', true);
require_once 'auth/config/database.php';

try {
    $result = DatabaseConfig::testConnection();
    echo "<pre>";
    print_r($result);
    echo "</pre>";
} catch (Exception $e) {
    echo "Database connection failed: " . $e->getMessage();
}
?>
```

Visit: `https://yourdomain.com/test-db.php`

#### Test Email Configuration
Create a test file `test-email.php`:
```php
<?php
define('AUTH_SYSTEM', true);
require_once 'auth/config/email.php';

try {
    $result = EmailConfig::sendEmail(
        'test@example.com',
        'Test Email',
        '<h1>Test Email</h1><p>If you receive this, email is working!</p>',
        'Test Email - If you receive this, email is working!'
    );
    
    echo "<pre>";
    print_r($result);
    echo "</pre>";
} catch (Exception $e) {
    echo "Email test failed: " . $e->getMessage();
}
?>
```

#### Access the Authentication System
Visit these URLs to test:
- Registration: `https://yourdomain.com/auth/register.php`
- Login: `https://yourdomain.com/auth/login.php`
- Dashboard: `https://yourdomain.com/auth/dashboard.php`

### 7. Production Optimizations

#### PHP Configuration (php.ini)
```ini
# Security settings
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log

# Session security
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Strict"
session.use_strict_mode = 1

# Upload limits
upload_max_filesize = 5M
post_max_size = 8M
max_execution_time = 30
memory_limit = 256M

# OPcache (recommended)
opcache.enable = 1
opcache.memory_consumption = 128
opcache.max_accelerated_files = 4000
opcache.revalidate_freq = 2
```

#### MySQL Optimization (my.cnf)
```ini
[mysqld]
# Performance tuning
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
query_cache_size = 64M
query_cache_type = 1
max_connections = 500

# Security
bind-address = 127.0.0.1
local-infile = 0
```

### 8. Security Checklist

- [ ] SSL certificate installed and configured
- [ ] Database user has minimal required privileges
- [ ] Strong database passwords used
- [ ] File permissions set correctly (644 for files, 755 for directories)
- [ ] Sensitive configuration files protected from web access
- [ ] Error reporting disabled in production
- [ ] Security headers configured
- [ ] Regular backups scheduled
- [ ] Log monitoring set up
- [ ] Firewall configured to allow only necessary ports

### 9. Monitoring and Maintenance

#### Log Files to Monitor
```bash
# PHP error logs
tail -f /var/log/php/error.log

# Web server logs
tail -f /var/log/apache2/error.log  # Apache
tail -f /var/log/nginx/error.log    # Nginx

# MySQL logs
tail -f /var/log/mysql/error.log
```

#### Regular Maintenance Tasks
```bash
# Weekly: Clean up expired tokens
mysql -u ecommerce_user -p ecommerce_auth -e "
DELETE FROM email_verification_tokens WHERE expires_at < NOW() AND used_at IS NULL;
DELETE FROM password_reset_tokens WHERE expires_at < NOW() AND used_at IS NULL;
DELETE FROM user_sessions WHERE expires_at < NOW();
"

# Monthly: Optimize database tables
mysql -u ecommerce_user -p ecommerce_auth -e "OPTIMIZE TABLE users, security_logs, user_sessions;"
```

### 10. Backup Strategy

#### Database Backup Script
Create `backup.sh`:
```bash
#!/bin/bash
BACKUP_DIR="/backups/ecommerce"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="ecommerce_auth"
DB_USER="ecommerce_user"
DB_PASS="your_password"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/db_backup_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/db_backup_$DATE.sql

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/db_backup_$DATE.sql.gz"
```

Make it executable and add to cron:
```bash
chmod +x backup.sh
crontab -e
# Add: 0 2 * * * /path/to/backup.sh
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors
```
Error: SQLSTATE[HY000] [2002] Connection refused
```
**Solution**: Check MySQL service and credentials
```bash
sudo systemctl status mysql
mysql -u ecommerce_user -p ecommerce_auth -e "SELECT 1;"
```

#### 2. Email Not Sending
```
Error: SMTP connect() failed
```
**Solution**: 
- Verify SMTP credentials
- Check firewall allows outbound port 587/465
- Test with `telnet smtp.provider.com 587`

#### 3. Session Issues
```
Error: session_start(): Cannot send session cache limiter
```
**Solution**: Ensure no output before session_start(), check PHP error logs

#### 4. File Permission Errors
```
Error: fopen(): failed to open stream: Permission denied
```
**Solution**: 
```bash
sudo chown -R www-data:www-data /path/to/auth/
sudo chmod -R 755 /path/to/auth/
```

### Getting Help

1. Check the error logs first
2. Verify all requirements are met
3. Test individual components (database, email, sessions)
4. Contact support: sumit140507@gmail.com

## Next Steps

After successful installation:
1. Create your first admin user via registration
2. Test all authentication flows
3. Customize email templates as needed
4. Implement additional features (2FA, social login, etc.)
5. Set up monitoring and alerting
6. Plan regular security updates

Your e-commerce authentication system is now ready for production use!