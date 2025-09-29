<?php
/**
 * Security Configuration
 * 
 * Comprehensive security constants, CSRF protection, rate limiting,
 * and other security measures for the authentication system.
 * 
 * @author Sumit
 * @version 1.0
 */

// Prevent direct access
if (!defined('AUTH_SYSTEM')) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access denied.');
}

class SecurityConfig {
    // Password requirements
    public const MIN_PASSWORD_LENGTH = 8;
    public const MAX_PASSWORD_LENGTH = 128;
    public const REQUIRE_UPPERCASE = true;
    public const REQUIRE_LOWERCASE = true;
    public const REQUIRE_NUMBERS = true;
    public const REQUIRE_SPECIAL_CHARS = true;
    public const SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    // Password hashing
    public const PASSWORD_HASH_ALGO = PASSWORD_ARGON2ID; // or PASSWORD_BCRYPT
    public const PASSWORD_HASH_OPTIONS = [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3,         // 3 threads
    ];
    
    // Session security
    public const SESSION_LIFETIME = 7200; // 2 hours in seconds
    public const SESSION_REGENERATE_INTERVAL = 300; // 5 minutes
    public const REMEMBER_ME_LIFETIME = 2592000; // 30 days
    public const MAX_CONCURRENT_SESSIONS = 3;
    
    // Rate limiting
    public const LOGIN_MAX_ATTEMPTS = 5;
    public const LOGIN_LOCKOUT_TIME = 900; // 15 minutes
    public const REGISTRATION_MAX_ATTEMPTS = 3;
    public const REGISTRATION_LOCKOUT_TIME = 3600; // 1 hour
    public const PASSWORD_RESET_MAX_ATTEMPTS = 3;
    public const PASSWORD_RESET_LOCKOUT_TIME = 3600; // 1 hour
    
    // Token security
    public const TOKEN_LENGTH = 64;
    public const VERIFICATION_TOKEN_EXPIRY = 86400; // 24 hours
    public const RESET_TOKEN_EXPIRY = 900; // 15 minutes
    public const CSRF_TOKEN_EXPIRY = 3600; // 1 hour
    
    // Security headers
    public const SECURITY_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()'
    ];
    
    // Input validation
    public const MAX_INPUT_LENGTH = 1000;
    public const ALLOWED_USERNAME_CHARS = '/^[a-zA-Z0-9_.-]+$/';
    public const ALLOWED_NAME_CHARS = '/^[a-zA-Z\s\'-]+$/u';
    public const ALLOWED_PHONE_CHARS = '/^[\d\s\-\+\(\)]+$/';
    
    // File upload security (if needed)
    public const MAX_UPLOAD_SIZE = 5242880; // 5MB
    public const ALLOWED_FILE_TYPES = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'];
    public const UPLOAD_PATH = '/uploads/';
    
    private static $csrfTokens = [];
    private static $rateLimits = [];
    
    /**
     * Initialize security configuration
     */
    public static function init(): void {
        // Start secure session
        self::startSecureSession();
        
        // Set security headers
        self::setSecurityHeaders();
        
        // Initialize CSRF protection
        self::initCSRFProtection();
        
        // Clean up expired data
        self::cleanup();
    }
    
    /**
     * Start secure session with proper configuration
     */
    public static function startSecureSession(): void {
        if (session_status() === PHP_SESSION_NONE) {
            // Configure session settings
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_lifetime', self::SESSION_LIFETIME);
            ini_set('session.gc_maxlifetime', self::SESSION_LIFETIME);
            
            // Generate secure session name
            session_name('AUTH_SESSION_' . hash('sha256', __DIR__));
            
            session_start();
            
            // Regenerate session ID periodically
            if (!isset($_SESSION['last_regeneration'])) {
                $_SESSION['last_regeneration'] = time();
            } elseif (time() - $_SESSION['last_regeneration'] > self::SESSION_REGENERATE_INTERVAL) {
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            }
            
            // Set session timeout
            if (!isset($_SESSION['session_timeout'])) {
                $_SESSION['session_timeout'] = time() + self::SESSION_LIFETIME;
            }
            
            // Check session timeout
            if (time() > $_SESSION['session_timeout']) {
                self::destroySession();
            }
        }
    }
    
    /**
     * Set security headers
     */
    public static function setSecurityHeaders(): void {
        foreach (self::SECURITY_HEADERS as $header => $value) {
            if (!headers_sent()) {
                header($header . ': ' . $value);
            }
        }
    }
    
    /**
     * Initialize CSRF protection
     */
    public static function initCSRFProtection(): void {
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        // Clean expired CSRF tokens
        $currentTime = time();
        foreach ($_SESSION['csrf_tokens'] as $token => $expiry) {
            if ($currentTime > $expiry) {
                unset($_SESSION['csrf_tokens'][$token]);
            }
        }
    }
    
    /**
     * Generate CSRF token
     * 
     * @param string $action
     * @return string
     */
    public static function generateCSRFToken(string $action = 'default'): string {
        $token = bin2hex(random_bytes(32));
        $expiry = time() + self::CSRF_TOKEN_EXPIRY;
        
        $_SESSION['csrf_tokens'][$token] = [
            'expiry' => $expiry,
            'action' => $action
        ];
        
        return $token;
    }
    
    /**
     * Validate CSRF token
     * 
     * @param string $token
     * @param string $action
     * @return bool
     */
    public static function validateCSRFToken(string $token, string $action = 'default'): bool {
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $tokenData = $_SESSION['csrf_tokens'][$token];
        
        // Check expiry
        if (time() > $tokenData['expiry']) {
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }
        
        // Check action match
        if ($tokenData['action'] !== $action) {
            return false;
        }
        
        // Remove token after use (one-time use)
        unset($_SESSION['csrf_tokens'][$token]);
        
        return true;
    }
    
    /**
     * Generate secure random token
     * 
     * @param int $length
     * @return string
     */
    public static function generateSecureToken(int $length = self::TOKEN_LENGTH): string {
        return bin2hex(random_bytes($length / 2));
    }
    
    /**
     * Hash password securely
     * 
     * @param string $password
     * @return string
     */
    public static function hashPassword(string $password): string {
        return password_hash($password, self::PASSWORD_HASH_ALGO, self::PASSWORD_HASH_OPTIONS);
    }
    
    /**
     * Verify password hash
     * 
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password, $hash);
    }
    
    /**
     * Check if password needs rehashing
     * 
     * @param string $hash
     * @return bool
     */
    public static function needsRehash(string $hash): bool {
        return password_needs_rehash($hash, self::PASSWORD_HASH_ALGO, self::PASSWORD_HASH_OPTIONS);
    }
    
    /**
     * Validate password strength
     * 
     * @param string $password
     * @return array
     */
    public static function validatePassword(string $password): array {
        $errors = [];
        $length = strlen($password);
        
        // Check length
        if ($length < self::MIN_PASSWORD_LENGTH) {
            $errors[] = 'Password must be at least ' . self::MIN_PASSWORD_LENGTH . ' characters long';
        }
        
        if ($length > self::MAX_PASSWORD_LENGTH) {
            $errors[] = 'Password must not exceed ' . self::MAX_PASSWORD_LENGTH . ' characters';
        }
        
        // Check character requirements
        if (self::REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        
        if (self::REQUIRE_LOWERCASE && !preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        
        if (self::REQUIRE_NUMBERS && !preg_match('/\d/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }
        
        if (self::REQUIRE_SPECIAL_CHARS && !preg_match('/[' . preg_quote(self::SPECIAL_CHARS, '/') . ']/', $password)) {
            $errors[] = 'Password must contain at least one special character (' . self::SPECIAL_CHARS . ')';
        }
        
        // Check for common weak patterns
        if (preg_match('/(.)\1{2,}/', $password)) {
            $errors[] = 'Password cannot contain more than 2 consecutive identical characters';
        }
        
        // Check against common passwords (basic check)
        $commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = 'Password is too common. Please choose a different password';
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'strength' => self::calculatePasswordStrength($password)
        ];
    }
    
    /**
     * Calculate password strength score
     * 
     * @param string $password
     * @return int Score from 0-100
     */
    private static function calculatePasswordStrength(string $password): int {
        $score = 0;
        $length = strlen($password);
        
        // Length bonus
        $score += min(25, $length * 2);
        
        // Character variety bonus
        if (preg_match('/[a-z]/', $password)) $score += 5;
        if (preg_match('/[A-Z]/', $password)) $score += 5;
        if (preg_match('/\d/', $password)) $score += 10;
        if (preg_match('/[' . preg_quote(self::SPECIAL_CHARS, '/') . ']/', $password)) $score += 15;
        
        // Complexity bonus
        $uniqueChars = count(array_unique(str_split($password)));
        $score += min(20, $uniqueChars * 2);
        
        // Pattern penalties
        if (preg_match('/(.)\1{2,}/', $password)) $score -= 10;
        if (preg_match('/123|abc|qwe/i', $password)) $score -= 10;
        
        return max(0, min(100, $score));
    }
    
    /**
     * Sanitize input to prevent XSS
     * 
     * @param string $input
     * @param bool $allowHTML
     * @return string
     */
    public static function sanitizeInput(string $input, bool $allowHTML = false): string {
        // Trim whitespace
        $input = trim($input);
        
        // Remove null bytes
        $input = str_replace("\0", "", $input);
        
        if (!$allowHTML) {
            // Remove HTML tags and encode special characters
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        } else {
            // Allow limited HTML tags
            $allowedTags = '<p><br><strong><em><u><a>';
            $input = strip_tags($input, $allowedTags);
        }
        
        // Limit length
        if (strlen($input) > self::MAX_INPUT_LENGTH) {
            $input = substr($input, 0, self::MAX_INPUT_LENGTH);
        }
        
        return $input;
    }
    
    /**
     * Validate input format
     * 
     * @param string $input
     * @param string $type
     * @return array
     */
    public static function validateInput(string $input, string $type): array {
        $errors = [];
        
        switch ($type) {
            case 'username':
                if (!preg_match(self::ALLOWED_USERNAME_CHARS, $input)) {
                    $errors[] = 'Username contains invalid characters';
                }
                if (strlen($input) < 3 || strlen($input) > 30) {
                    $errors[] = 'Username must be 3-30 characters long';
                }
                break;
                
            case 'email':
                if (!filter_var($input, FILTER_VALIDATE_EMAIL)) {
                    $errors[] = 'Invalid email address format';
                }
                if (strlen($input) > 255) {
                    $errors[] = 'Email address is too long';
                }
                break;
                
            case 'name':
                if (!preg_match(self::ALLOWED_NAME_CHARS, $input)) {
                    $errors[] = 'Name contains invalid characters';
                }
                if (strlen($input) > 100) {
                    $errors[] = 'Name is too long';
                }
                break;
                
            case 'phone':
                if (!preg_match(self::ALLOWED_PHONE_CHARS, $input)) {
                    $errors[] = 'Phone number contains invalid characters';
                }
                if (strlen($input) > 20) {
                    $errors[] = 'Phone number is too long';
                }
                break;
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
    
    /**
     * Check rate limiting
     * 
     * @param string $action
     * @param string $identifier
     * @return array
     */
    public static function checkRateLimit(string $action, string $identifier): array {
        $key = $action . '_' . hash('sha256', $identifier);
        $currentTime = time();
        
        if (!isset(self::$rateLimits[$key])) {
            self::$rateLimits[$key] = ['count' => 0, 'reset_time' => 0];
        }
        
        $rateData = &self::$rateLimits[$key];
        
        // Get limits for action
        switch ($action) {
            case 'login':
                $maxAttempts = self::LOGIN_MAX_ATTEMPTS;
                $lockoutTime = self::LOGIN_LOCKOUT_TIME;
                break;
            case 'registration':
                $maxAttempts = self::REGISTRATION_MAX_ATTEMPTS;
                $lockoutTime = self::REGISTRATION_LOCKOUT_TIME;
                break;
            case 'password_reset':
                $maxAttempts = self::PASSWORD_RESET_MAX_ATTEMPTS;
                $lockoutTime = self::PASSWORD_RESET_LOCKOUT_TIME;
                break;
            default:
                $maxAttempts = 10;
                $lockoutTime = 3600;
        }
        
        // Reset counter if lockout time has passed
        if ($currentTime > $rateData['reset_time']) {
            $rateData['count'] = 0;
            $rateData['reset_time'] = 0;
        }
        
        // Check if rate limit exceeded
        if ($rateData['count'] >= $maxAttempts) {
            return [
                'allowed' => false,
                'message' => 'Too many attempts. Please try again later.',
                'reset_time' => $rateData['reset_time']
            ];
        }
        
        return ['allowed' => true];
    }
    
    /**
     * Record rate limit attempt
     * 
     * @param string $action
     * @param string $identifier
     */
    public static function recordAttempt(string $action, string $identifier): void {
        $key = $action . '_' . hash('sha256', $identifier);
        $currentTime = time();
        
        if (!isset(self::$rateLimits[$key])) {
            self::$rateLimits[$key] = ['count' => 0, 'reset_time' => 0];
        }
        
        $rateData = &self::$rateLimits[$key];
        $rateData['count']++;
        
        // Set reset time based on action
        switch ($action) {
            case 'login':
                $lockoutTime = self::LOGIN_LOCKOUT_TIME;
                break;
            case 'registration':
                $lockoutTime = self::REGISTRATION_LOCKOUT_TIME;
                break;
            case 'password_reset':
                $lockoutTime = self::PASSWORD_RESET_LOCKOUT_TIME;
                break;
            default:
                $lockoutTime = 3600;
        }
        
        $rateData['reset_time'] = $currentTime + $lockoutTime;
    }
    
    /**
     * Get client IP address
     * 
     * @return string
     */
    public static function getClientIP(): string {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (isset($_SERVER[$key]) && !empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Get user agent
     * 
     * @return string
     */
    public static function getUserAgent(): string {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    }
    
    /**
     * Destroy session securely
     */
    public static function destroySession(): void {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            
            // Delete session cookie
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            
            session_destroy();
        }
    }
    
    /**
     * Clean up expired data
     */
    public static function cleanup(): void {
        // This should be called periodically to clean up expired rate limit data
        $currentTime = time();
        
        foreach (self::$rateLimits as $key => $data) {
            if ($currentTime > $data['reset_time']) {
                unset(self::$rateLimits[$key]);
            }
        }
    }
    
    /**
     * Log security event
     * 
     * @param string $event
     * @param array $details
     */
    public static function logSecurityEvent(string $event, array $details = []): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'ip' => self::getClientIP(),
            'user_agent' => self::getUserAgent(),
            'session_id' => session_id(),
            'details' => $details
        ];
        
        // In production, this should write to a secure log file or database
        error_log('Security Event: ' . json_encode($logData));
    }
}

// Initialize security when this file is included
SecurityConfig::init();

?>