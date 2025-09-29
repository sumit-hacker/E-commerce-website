<?php
/**
 * Email Configuration
 * 
 * SMTP email configuration for SendGrid, Mailgun, and other providers
 * with failover support and template management.
 * 
 * @author Sumit
 * @version 1.0
 */

// Prevent direct access
if (!defined('AUTH_SYSTEM')) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access denied.');
}

class EmailConfig {
    // Primary SMTP Configuration (SendGrid example)
    private const SMTP_HOST = 'smtp.sendgrid.net';
    private const SMTP_PORT = 587;
    private const SMTP_USERNAME = 'apikey'; // SendGrid uses 'apikey' as username
    private const SMTP_PASSWORD = 'your-sendgrid-api-key-here';
    private const SMTP_ENCRYPTION = 'tls'; // 'tls' or 'ssl'
    
    // Backup SMTP Configuration (Mailgun example)
    private const BACKUP_SMTP_HOST = 'smtp.mailgun.org';
    private const BACKUP_SMTP_PORT = 587;
    private const BACKUP_SMTP_USERNAME = 'postmaster@your-domain.mailgun.org';
    private const BACKUP_SMTP_PASSWORD = 'your-mailgun-password';
    private const BACKUP_SMTP_ENCRYPTION = 'tls';
    
    // Email sender configuration
    private const FROM_EMAIL = 'noreply@your-domain.com';
    private const FROM_NAME = 'E-Commerce Authentication';
    private const REPLY_TO_EMAIL = 'support@your-domain.com';
    private const REPLY_TO_NAME = 'Support Team';
    
    // Email settings
    private const MAX_RETRIES = 3;
    private const RETRY_DELAY = 2; // seconds
    private const EMAIL_TIMEOUT = 30; // seconds
    private const MAX_RECIPIENTS = 50; // per batch
    
    // Rate limiting
    private const RATE_LIMIT_WINDOW = 3600; // 1 hour in seconds
    private const MAX_EMAILS_PER_HOUR = 100;
    private const MAX_EMAILS_PER_USER_HOUR = 5;
    
    private static $instance = null;
    private static $emailCount = 0;
    private static $userEmailCount = [];
    
    /**
     * Get singleton instance
     * 
     * @return EmailConfig
     */
    public static function getInstance(): self {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Send email with automatic failover and retry logic
     * 
     * @param string $to Recipient email
     * @param string $subject Email subject
     * @param string $htmlBody HTML email body
     * @param string $textBody Plain text email body (optional)
     * @param array $attachments File attachments (optional)
     * @return array Result array with success status and message
     */
    public static function sendEmail(
        string $to, 
        string $subject, 
        string $htmlBody, 
        string $textBody = '', 
        array $attachments = []
    ): array {
        
        // Validate email address
        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'Invalid email address'];
        }
        
        // Check rate limits
        $rateLimitCheck = self::checkRateLimit($to);
        if (!$rateLimitCheck['allowed']) {
            return ['success' => false, 'error' => $rateLimitCheck['message']];
        }
        
        // Try primary SMTP first, then backup
        $configs = [
            [
                'host' => self::SMTP_HOST,
                'port' => self::SMTP_PORT,
                'username' => self::SMTP_USERNAME,
                'password' => self::SMTP_PASSWORD,
                'encryption' => self::SMTP_ENCRYPTION,
                'name' => 'primary'
            ],
            [
                'host' => self::BACKUP_SMTP_HOST,
                'port' => self::BACKUP_SMTP_PORT,
                'username' => self::BACKUP_SMTP_USERNAME,
                'password' => self::BACKUP_SMTP_PASSWORD,
                'encryption' => self::BACKUP_SMTP_ENCRYPTION,
                'name' => 'backup'
            ]
        ];
        
        foreach ($configs as $config) {
            $result = self::attemptSendEmail($to, $subject, $htmlBody, $textBody, $config, $attachments);
            
            if ($result['success']) {
                self::updateEmailCount($to);
                self::logEmailEvent('email_sent', [
                    'to' => $to,
                    'subject' => $subject,
                    'smtp' => $config['name'],
                    'retries' => $result['retries'] ?? 0
                ]);
                return $result;
            }
            
            // Log failure and try next config
            self::logEmailEvent('smtp_failed', [
                'to' => $to,
                'smtp' => $config['name'],
                'error' => $result['error']
            ]);
        }
        
        // All SMTP configs failed
        return [
            'success' => false, 
            'error' => 'All SMTP servers failed. Please try again later.'
        ];
    }
    
    /**
     * Attempt to send email with specific SMTP configuration
     * 
     * @param string $to
     * @param string $subject
     * @param string $htmlBody
     * @param string $textBody
     * @param array $config
     * @param array $attachments
     * @return array
     */
    private static function attemptSendEmail(
        string $to, 
        string $subject, 
        string $htmlBody, 
        string $textBody, 
        array $config,
        array $attachments = []
    ): array {
        
        $retries = 0;
        $lastError = '';
        
        while ($retries < self::MAX_RETRIES) {
            try {
                // Prepare email headers
                $headers = self::buildEmailHeaders($config);
                
                // Build email body
                $emailBody = self::buildEmailBody($htmlBody, $textBody, $attachments);
                
                // Send email using PHP mail() function with SMTP headers
                // In production, use PHPMailer or SwiftMailer for better SMTP support
                $success = mail($to, $subject, $emailBody, $headers);
                
                if ($success) {
                    return [
                        'success' => true,
                        'message' => 'Email sent successfully',
                        'retries' => $retries
                    ];
                } else {
                    throw new Exception('mail() function returned false');
                }
                
            } catch (Exception $e) {
                $lastError = $e->getMessage();
                $retries++;
                
                if ($retries < self::MAX_RETRIES) {
                    sleep(self::RETRY_DELAY * $retries); // Exponential backoff
                }
            }
        }
        
        return [
            'success' => false,
            'error' => "Failed after {$retries} retries: {$lastError}"
        ];
    }
    
    /**
     * Build email headers
     * 
     * @param array $config
     * @return string
     */
    private static function buildEmailHeaders(array $config): string {
        $headers = [];
        
        // From header
        $headers[] = 'From: ' . self::FROM_NAME . ' <' . self::FROM_EMAIL . '>';
        $headers[] = 'Reply-To: ' . self::REPLY_TO_NAME . ' <' . self::REPLY_TO_EMAIL . '>';
        
        // MIME headers for HTML email
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-Type: text/html; charset=UTF-8';
        $headers[] = 'Content-Transfer-Encoding: 8bit';
        
        // Security headers
        $headers[] = 'X-Mailer: E-Commerce Auth System';
        $headers[] = 'X-Priority: 3';
        $headers[] = 'Message-ID: <' . uniqid() . '@' . $_SERVER['HTTP_HOST'] . '>';
        
        return implode("\r\n", $headers);
    }
    
    /**
     * Build email body with HTML and text versions
     * 
     * @param string $htmlBody
     * @param string $textBody
     * @param array $attachments
     * @return string
     */
    private static function buildEmailBody(string $htmlBody, string $textBody, array $attachments): string {
        if (empty($textBody)) {
            $textBody = strip_tags($htmlBody);
        }
        
        // For now, return HTML body
        // In production, create proper multipart/alternative structure
        return $htmlBody;
    }
    
    /**
     * Check rate limiting for email sending
     * 
     * @param string $to
     * @return array
     */
    private static function checkRateLimit(string $to): array {
        // Global rate limit check
        if (self::$emailCount >= self::MAX_EMAILS_PER_HOUR) {
            return [
                'allowed' => false,
                'message' => 'Global email rate limit exceeded. Please try again later.'
            ];
        }
        
        // User-specific rate limit check
        $userEmail = strtolower($to);
        $currentTime = time();
        
        // Clean old entries
        foreach (self::$userEmailCount as $email => $data) {
            if ($currentTime - $data['timestamp'] > self::RATE_LIMIT_WINDOW) {
                unset(self::$userEmailCount[$email]);
            }
        }
        
        // Check user limit
        if (isset(self::$userEmailCount[$userEmail])) {
            if (self::$userEmailCount[$userEmail]['count'] >= self::MAX_EMAILS_PER_USER_HOUR) {
                return [
                    'allowed' => false,
                    'message' => 'Too many emails sent to this address. Please try again later.'
                ];
            }
        }
        
        return ['allowed' => true];
    }
    
    /**
     * Update email count for rate limiting
     * 
     * @param string $to
     */
    private static function updateEmailCount(string $to): void {
        self::$emailCount++;
        
        $userEmail = strtolower($to);
        $currentTime = time();
        
        if (!isset(self::$userEmailCount[$userEmail])) {
            self::$userEmailCount[$userEmail] = ['count' => 0, 'timestamp' => $currentTime];
        }
        
        self::$userEmailCount[$userEmail]['count']++;
        self::$userEmailCount[$userEmail]['timestamp'] = $currentTime;
    }
    
    /**
     * Send verification email
     * 
     * @param string $to
     * @param string $username
     * @param string $verificationToken
     * @return array
     */
    public static function sendVerificationEmail(string $to, string $username, string $verificationToken): array {
        $subject = 'Verify Your Email Address';
        
        $verificationLink = self::getBaseUrl() . '/auth/verify.php?token=' . urlencode($verificationToken);
        
        $htmlBody = self::getEmailTemplate('verification', [
            'username' => $username,
            'verification_link' => $verificationLink,
            'expires_in' => '24 hours'
        ]);
        
        return self::sendEmail($to, $subject, $htmlBody);
    }
    
    /**
     * Send password reset email
     * 
     * @param string $to
     * @param string $username
     * @param string $resetToken
     * @return array
     */
    public static function sendPasswordResetEmail(string $to, string $username, string $resetToken): array {
        $subject = 'Reset Your Password';
        
        $resetLink = self::getBaseUrl() . '/auth/reset-password.php?token=' . urlencode($resetToken);
        
        $htmlBody = self::getEmailTemplate('password_reset', [
            'username' => $username,
            'reset_link' => $resetLink,
            'expires_in' => '15 minutes'
        ]);
        
        return self::sendEmail($to, $subject, $htmlBody);
    }
    
    /**
     * Get email template with variables replaced
     * 
     * @param string $template
     * @param array $variables
     * @return string
     */
    private static function getEmailTemplate(string $template, array $variables): string {
        $templatePath = __DIR__ . '/../templates/email-' . $template . '.html';
        
        if (!file_exists($templatePath)) {
            // Fallback to basic template
            return self::getBasicEmailTemplate($template, $variables);
        }
        
        $content = file_get_contents($templatePath);
        
        // Replace variables
        foreach ($variables as $key => $value) {
            $content = str_replace('{{' . $key . '}}', htmlspecialchars($value), $content);
        }
        
        return $content;
    }
    
    /**
     * Get basic email template (fallback)
     * 
     * @param string $template
     * @param array $variables
     * @return string
     */
    private static function getBasicEmailTemplate(string $template, array $variables): string {
        if ($template === 'verification') {
            return '
                <h2>Email Verification</h2>
                <p>Hello ' . htmlspecialchars($variables['username']) . ',</p>
                <p>Please click the link below to verify your email address:</p>
                <p><a href="' . htmlspecialchars($variables['verification_link']) . '">Verify Email</a></p>
                <p>This link will expire in ' . htmlspecialchars($variables['expires_in']) . '.</p>
                <p>If you did not create an account, please ignore this email.</p>
            ';
        } elseif ($template === 'password_reset') {
            return '
                <h2>Password Reset</h2>
                <p>Hello ' . htmlspecialchars($variables['username']) . ',</p>
                <p>Please click the link below to reset your password:</p>
                <p><a href="' . htmlspecialchars($variables['reset_link']) . '">Reset Password</a></p>
                <p>This link will expire in ' . htmlspecialchars($variables['expires_in']) . '.</p>
                <p>If you did not request a password reset, please ignore this email.</p>
            ';
        }
        
        return '<p>Email content not available.</p>';
    }
    
    /**
     * Get base URL for email links
     * 
     * @return string
     */
    private static function getBaseUrl(): string {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $protocol . '://' . $host;
    }
    
    /**
     * Log email events
     * 
     * @param string $event
     * @param array $details
     */
    private static function logEmailEvent(string $event, array $details = []): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'details' => $details
        ];
        
        error_log('Email Event: ' . json_encode($logData));
    }
    
    /**
     * Get email statistics
     * 
     * @return array
     */
    public static function getStats(): array {
        return [
            'emails_sent_today' => self::$emailCount,
            'max_per_hour' => self::MAX_EMAILS_PER_HOUR,
            'user_counts' => count(self::$userEmailCount),
            'rate_limit_window' => self::RATE_LIMIT_WINDOW,
            'max_per_user_hour' => self::MAX_EMAILS_PER_USER_HOUR
        ];
    }
}

// Configuration for different environments
if (defined('ENVIRONMENT')) {
    switch (ENVIRONMENT) {
        case 'development':
            // Use local SMTP or mail testing service
            break;
        case 'staging':
            // Use staging email configuration
            break;
        case 'production':
            // Use production email service
            break;
    }
}

?>