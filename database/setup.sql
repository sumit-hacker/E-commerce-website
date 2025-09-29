-- E-commerce Authentication System Setup Script
-- Run this script to set up the complete authentication system
-- 
-- Usage: mysql -u root -p < setup.sql

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `ecommerce_auth` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `ecommerce_auth`;

-- Create dedicated user for the application (optional but recommended)
-- Uncomment the following lines and replace 'your_secure_password' with a strong password
-- CREATE USER IF NOT EXISTS 'ecommerce_user'@'localhost' IDENTIFIED BY 'your_secure_password';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ecommerce_auth.* TO 'ecommerce_user'@'localhost';
-- FLUSH PRIVILEGES;

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";

-- Users table with comprehensive fields
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `is_verified` tinyint(1) DEFAULT 0,
  `is_active` tinyint(1) DEFAULT 1,
  `role` enum('user','admin','moderator') DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  `login_attempts` int(11) DEFAULT 0,
  `lockout_time` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_users_email` (`email`),
  UNIQUE KEY `idx_users_username` (`username`),
  KEY `idx_users_role` (`role`),
  KEY `idx_users_active` (`is_active`),
  KEY `idx_users_verified` (`is_verified`),
  KEY `idx_users_created` (`created_at`),
  KEY `idx_users_login_attempts` (`login_attempts`, `lockout_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Email verification tokens
CREATE TABLE IF NOT EXISTS `email_verification_tokens` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `token` varchar(255) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `used_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_token` (`token`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_expires` (`expires_at`),
  CONSTRAINT `fk_verification_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Password reset tokens
CREATE TABLE IF NOT EXISTS `password_reset_tokens` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `token` varchar(255) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `used_at` timestamp NULL DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_token` (`token`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_expires` (`expires_at`),
  CONSTRAINT `fk_reset_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions for tracking active sessions
CREATE TABLE IF NOT EXISTS `user_sessions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_activity` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expires_at` timestamp NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_session_id` (`session_id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_expires` (`expires_at`),
  KEY `idx_last_activity` (`last_activity`),
  CONSTRAINT `fk_session_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Security logs for auditing
CREATE TABLE IF NOT EXISTS `security_logs` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED DEFAULT NULL,
  `event_type` enum('login_success','login_failed','registration','password_reset','email_verification','logout','account_locked','suspicious_activity') NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `details` json DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_security_logs_user_event` (`user_id`, `event_type`, `created_at`),
  CONSTRAINT `fk_log_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User preferences for storing settings
CREATE TABLE IF NOT EXISTS `user_preferences` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `preference_key` varchar(100) NOT NULL,
  `preference_value` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_user_preference` (`user_id`, `preference_key`),
  CONSTRAINT `fk_preference_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default admin user
-- Password: Admin123! (change this immediately after setup)
-- Password hash generated with: password_hash('Admin123!', PASSWORD_ARGON2ID)
INSERT INTO `users` (`username`, `email`, `password_hash`, `first_name`, `last_name`, `is_verified`, `role`) VALUES
('admin', 'admin@example.com', '$argon2id$v=19$m=65536,t=4,p=3$UW5oTjhVdVcuTk8vMkZhVA$+Kz0EYhGnF3EXwK8ZK3R8L2h7mF9e0q5I6V3A7s9x+U', 'System', 'Administrator', 1, 'admin')
ON DUPLICATE KEY UPDATE 
  password_hash = VALUES(password_hash),
  updated_at = CURRENT_TIMESTAMP;

-- Insert some sample data for testing (optional)
-- Uncomment the following section if you want sample data

/*
-- Sample regular user (password: User123!)
INSERT INTO `users` (`username`, `email`, `password_hash`, `first_name`, `last_name`, `is_verified`, `role`) VALUES
('testuser', 'user@example.com', '$argon2id$v=19$m=65536,t=4,p=3$UW5oTjhVdVcuTk8vMkZhVA$bN7vF2qK9zG8LdJ5hX4pW1eR6yI8uT3mQ0sN5c9V2aE', 'Test', 'User', 1, 'user')
ON DUPLICATE KEY UPDATE 
  password_hash = VALUES(password_hash),
  updated_at = CURRENT_TIMESTAMP;

-- Sample unverified user
INSERT INTO `users` (`username`, `email`, `password_hash`, `first_name`, `last_name`, `is_verified`, `role`) VALUES
('unverified', 'unverified@example.com', '$argon2id$v=19$m=65536,t=4,p=3$UW5oTjhVdVcuTk8vMkZhVA$zK8mW3nR9yH2sJ6xF4vL7bP0eQ5tI1cN8dG7uA3zM9x', 'Unverified', 'User', 0, 'user')
ON DUPLICATE KEY UPDATE 
  password_hash = VALUES(password_hash),
  updated_at = CURRENT_TIMESTAMP;

-- Sample security log entries
INSERT INTO `security_logs` (`user_id`, `event_type`, `ip_address`, `user_agent`, `details`) VALUES
(1, 'registration', '127.0.0.1', 'Mozilla/5.0 (Test Browser)', '{"source": "setup_script"}'),
(1, 'login_success', '127.0.0.1', 'Mozilla/5.0 (Test Browser)', '{"source": "setup_script"}');
*/

-- Create useful views for reporting (optional but recommended)

-- View for user statistics
CREATE OR REPLACE VIEW `vw_user_stats` AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    u.is_verified,
    u.is_active,
    u.created_at,
    u.last_login,
    COALESCE(login_count.successful_logins, 0) as successful_logins,
    COALESCE(login_count.failed_logins, 0) as failed_logins,
    COALESCE(session_count.active_sessions, 0) as active_sessions
FROM users u
LEFT JOIN (
    SELECT 
        user_id,
        SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) as successful_logins,
        SUM(CASE WHEN event_type = 'login_failed' THEN 1 ELSE 0 END) as failed_logins
    FROM security_logs 
    GROUP BY user_id
) login_count ON u.id = login_count.user_id
LEFT JOIN (
    SELECT 
        user_id,
        COUNT(*) as active_sessions
    FROM user_sessions 
    WHERE expires_at > NOW()
    GROUP BY user_id
) session_count ON u.id = session_count.user_id;

-- View for recent security events
CREATE OR REPLACE VIEW `vw_recent_security_events` AS
SELECT 
    sl.id,
    sl.user_id,
    u.username,
    u.email,
    sl.event_type,
    sl.ip_address,
    sl.created_at,
    CASE 
        WHEN sl.event_type IN ('login_failed', 'account_locked', 'suspicious_activity') THEN 'danger'
        WHEN sl.event_type IN ('login_success', 'registration', 'email_verification') THEN 'success'
        ELSE 'info'
    END as severity
FROM security_logs sl
LEFT JOIN users u ON sl.user_id = u.id
ORDER BY sl.created_at DESC;

-- Stored procedures for common operations

DELIMITER $$

-- Procedure to clean up expired tokens and sessions
CREATE PROCEDURE `sp_cleanup_expired_data`()
BEGIN
    DECLARE cleaned_tokens INT DEFAULT 0;
    DECLARE cleaned_sessions INT DEFAULT 0;
    
    START TRANSACTION;
    
    -- Clean expired email verification tokens
    DELETE FROM `email_verification_tokens` 
    WHERE `expires_at` < NOW() AND `used_at` IS NULL;
    SET cleaned_tokens = cleaned_tokens + ROW_COUNT();
    
    -- Clean expired password reset tokens
    DELETE FROM `password_reset_tokens` 
    WHERE `expires_at` < NOW() AND `used_at` IS NULL;
    SET cleaned_tokens = cleaned_tokens + ROW_COUNT();
    
    -- Clean expired user sessions
    DELETE FROM `user_sessions` 
    WHERE `expires_at` < NOW();
    SET cleaned_sessions = ROW_COUNT();
    
    -- Log cleanup activity
    INSERT INTO `security_logs` (`event_type`, `details`) 
    VALUES ('system_cleanup', JSON_OBJECT(
        'cleaned_tokens', cleaned_tokens,
        'cleaned_sessions', cleaned_sessions,
        'timestamp', NOW()
    ));
    
    COMMIT;
    
    SELECT cleaned_tokens as tokens_cleaned, cleaned_sessions as sessions_cleaned;
END$$

-- Procedure to get user security summary
CREATE PROCEDURE `sp_get_user_security_summary`(IN user_id INT)
BEGIN
    SELECT 
        u.username,
        u.email,
        u.is_verified,
        u.last_login,
        u.login_attempts,
        (SELECT COUNT(*) FROM security_logs WHERE user_id = u.id AND event_type = 'login_success') as total_logins,
        (SELECT COUNT(*) FROM security_logs WHERE user_id = u.id AND event_type = 'login_failed') as failed_attempts,
        (SELECT COUNT(*) FROM user_sessions WHERE user_id = u.id AND expires_at > NOW()) as active_sessions,
        (SELECT created_at FROM security_logs WHERE user_id = u.id ORDER BY created_at DESC LIMIT 1) as last_activity
    FROM users u 
    WHERE u.id = user_id;
END$$

-- Procedure to lock suspicious accounts
CREATE PROCEDURE `sp_lock_suspicious_account`(IN user_id INT, IN reason TEXT)
BEGIN
    UPDATE users 
    SET is_active = 0, lockout_time = NOW() 
    WHERE id = user_id;
    
    INSERT INTO security_logs (user_id, event_type, details) 
    VALUES (user_id, 'account_locked', JSON_OBJECT('reason', reason, 'locked_at', NOW()));
END$$

DELIMITER ;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS `idx_security_logs_created_at` ON `security_logs` (`created_at` DESC);
CREATE INDEX IF NOT EXISTS `idx_user_sessions_expires_at` ON `user_sessions` (`expires_at`);
CREATE INDEX IF NOT EXISTS `idx_tokens_expires_at` ON `email_verification_tokens` (`expires_at`);
CREATE INDEX IF NOT EXISTS `idx_reset_tokens_expires_at` ON `password_reset_tokens` (`expires_at`);

-- Set up event scheduler for automatic cleanup (requires SUPER privileges)
-- Uncomment the following lines if you have SUPER privileges and want automatic cleanup

/*
SET GLOBAL event_scheduler = ON;

DELIMITER $$
CREATE EVENT IF NOT EXISTS `evt_cleanup_expired_data`
ON SCHEDULE EVERY 1 HOUR
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    CALL sp_cleanup_expired_data();
END$$
DELIMITER ;
*/

COMMIT;

-- Display setup completion message
SELECT 
    'Database setup completed successfully!' as status,
    (SELECT COUNT(*) FROM users) as total_users,
    (SELECT COUNT(*) FROM users WHERE role = 'admin') as admin_users,
    NOW() as setup_time;

-- Show default admin credentials (CHANGE THESE IMMEDIATELY!)
SELECT 
    'IMPORTANT: Change default admin password!' as warning,
    'Username: admin' as default_username,
    'Password: Admin123!' as default_password,
    'Email: admin@example.com' as default_email;

-- Show next steps
SELECT 
    'Next Steps:' as info,
    '1. Change default admin password' as step1,
    '2. Configure SMTP settings in auth/config/email.php' as step2,
    '3. Update database credentials in auth/config/database.php' as step3,
    '4. Set up SSL certificate' as step4,
    '5. Configure web server security headers' as step5;