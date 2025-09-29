<?php
/**
 * Secure Session Management
 * 
 * Comprehensive session handling with security features,
 * session fixation prevention, and user state management.
 * 
 * @author Sumit
 * @version 1.0
 */

// Define AUTH_SYSTEM constant to allow config files to load
define('AUTH_SYSTEM', true);

// Include required configuration
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/security.php';

class SessionManager {
    
    private static $initialized = false;
    private static $sessionData = [];
    
    /**
     * Initialize secure session management
     * 
     * @return bool
     */
    public static function init(): bool {
        if (self::$initialized) {
            return true;
        }
        
        try {
            // Configure session settings before starting
            self::configureSession();
            
            // Start session
            if (session_status() === PHP_SESSION_NONE) {
                if (!session_start()) {
                    throw new Exception('Failed to start session');
                }
            }
            
            // Initialize session security
            self::initializeSecurity();
            
            // Load session data
            self::loadSessionData();
            
            self::$initialized = true;
            return true;
            
        } catch (Exception $e) {
            error_log('Session initialization failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Configure session settings for security
     */
    private static function configureSession(): void {
        // Session cookie settings
        $cookieParams = [
            'lifetime' => SecurityConfig::SESSION_LIFETIME,
            'path' => '/',
            'domain' => $_SERVER['HTTP_HOST'] ?? '',
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
            'httponly' => true,
            'samesite' => 'Strict'
        ];
        
        session_set_cookie_params($cookieParams);
        
        // Session configuration
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_cookies', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', $cookieParams['secure'] ? '1' : '0');
        ini_set('session.gc_maxlifetime', SecurityConfig::SESSION_LIFETIME);
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '100');
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');
        
        // Generate secure session name
        $sessionName = 'AUTHSESS_' . substr(hash('sha256', __DIR__), 0, 8);
        session_name($sessionName);
    }
    
    /**
     * Initialize session security measures
     */
    private static function initializeSecurity(): void {
        $currentTime = time();
        
        // Check if this is a new session
        if (!isset($_SESSION['initialized'])) {
            $_SESSION['initialized'] = true;
            $_SESSION['created_at'] = $currentTime;
            $_SESSION['ip_address'] = SecurityConfig::getClientIP();
            $_SESSION['user_agent'] = SecurityConfig::getUserAgent();
            $_SESSION['last_activity'] = $currentTime;
            $_SESSION['csrf_tokens'] = [];
            return;
        }
        
        // Validate session integrity
        self::validateSessionIntegrity();
        
        // Check session timeout
        if (self::isSessionExpired()) {
            self::destroy();
            throw new Exception('Session expired');
        }
        
        // Regenerate session ID periodically
        if (self::shouldRegenerateId()) {
            self::regenerateId();
        }
        
        // Update last activity
        $_SESSION['last_activity'] = $currentTime;
    }
    
    /**
     * Validate session integrity
     */
    private static function validateSessionIntegrity(): void {
        // Check IP address (optional, can be disabled for mobile users)
        $checkIP = true; // Set to false if users have dynamic IPs
        if ($checkIP && isset($_SESSION['ip_address'])) {
            $currentIP = SecurityConfig::getClientIP();
            if ($_SESSION['ip_address'] !== $currentIP) {
                self::logSecurityEvent('session_ip_mismatch', [
                    'original_ip' => $_SESSION['ip_address'],
                    'current_ip' => $currentIP
                ]);
                // Optionally destroy session for security
                // self::destroy();
                // throw new Exception('Session IP mismatch');
            }
        }
        
        // Check user agent
        if (isset($_SESSION['user_agent'])) {
            $currentUA = SecurityConfig::getUserAgent();
            if ($_SESSION['user_agent'] !== $currentUA) {
                self::logSecurityEvent('session_ua_mismatch', [
                    'original_ua' => $_SESSION['user_agent'],
                    'current_ua' => $currentUA
                ]);
                // Log but don't destroy (user agents can change)
            }
        }
        
        // Check session age
        if (isset($_SESSION['created_at'])) {
            $maxAge = 24 * 3600; // 24 hours maximum session age
            if (time() - $_SESSION['created_at'] > $maxAge) {
                self::logSecurityEvent('session_too_old');
                self::destroy();
                throw new Exception('Session too old');
            }
        }
    }
    
    /**
     * Check if session is expired
     */
    private static function isSessionExpired(): bool {
        if (!isset($_SESSION['last_activity'])) {
            return true;
        }
        
        $inactiveTime = time() - $_SESSION['last_activity'];
        $maxInactive = SecurityConfig::SESSION_LIFETIME;
        
        return $inactiveTime > $maxInactive;
    }
    
    /**
     * Check if session ID should be regenerated
     */
    private static function shouldRegenerateId(): bool {
        if (!isset($_SESSION['last_regeneration'])) {
            return true;
        }
        
        $timeSinceRegeneration = time() - $_SESSION['last_regeneration'];
        return $timeSinceRegeneration > SecurityConfig::SESSION_REGENERATE_INTERVAL;
    }
    
    /**
     * Regenerate session ID
     */
    public static function regenerateId(): bool {
        try {
            $oldSessionId = session_id();
            
            if (!session_regenerate_id(true)) {
                throw new Exception('Failed to regenerate session ID');
            }
            
            $_SESSION['last_regeneration'] = time();
            
            // Update database record if user is logged in
            if (isset($_SESSION['user_id'])) {
                self::updateSessionInDatabase($oldSessionId, session_id());
            }
            
            self::logSecurityEvent('session_regenerated', [
                'old_session_id' => substr($oldSessionId, 0, 10) . '...',
                'new_session_id' => substr(session_id(), 0, 10) . '...'
            ]);
            
            return true;
            
        } catch (Exception $e) {
            error_log('Session regeneration failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Set session value
     */
    public static function set(string $key, $value): void {
        self::init();
        $_SESSION[$key] = $value;
        self::$sessionData[$key] = $value;
    }
    
    /**
     * Get session value
     */
    public static function get(string $key, $default = null) {
        self::init();
        return $_SESSION[$key] ?? $default;
    }
    
    /**
     * Check if session key exists
     */
    public static function has(string $key): bool {
        self::init();
        return isset($_SESSION[$key]);
    }
    
    /**
     * Remove session value
     */
    public static function remove(string $key): void {
        self::init();
        unset($_SESSION[$key]);
        unset(self::$sessionData[$key]);
    }
    
    /**
     * Clear all session data except system data
     */
    public static function clear(): void {
        self::init();
        
        // Preserve system session data
        $systemKeys = [
            'initialized', 'created_at', 'ip_address', 'user_agent',
            'last_activity', 'last_regeneration', 'csrf_tokens'
        ];
        
        $preservedData = [];
        foreach ($systemKeys as $key) {
            if (isset($_SESSION[$key])) {
                $preservedData[$key] = $_SESSION[$key];
            }
        }
        
        $_SESSION = $preservedData;
        self::$sessionData = [];
    }
    
    /**
     * Destroy session completely
     */
    public static function destroy(): bool {
        try {
            $userId = $_SESSION['user_id'] ?? null;
            $sessionId = session_id();
            
            // Remove from database
            if ($userId && $sessionId) {
                self::removeSessionFromDatabase($userId, $sessionId);
            }
            
            // Clear session data
            $_SESSION = [];
            self::$sessionData = [];
            
            // Delete session cookie
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(
                    session_name(),
                    '',
                    time() - 42000,
                    $params["path"],
                    $params["domain"],
                    $params["secure"],
                    $params["httponly"]
                );
            }
            
            // Destroy session
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_destroy();
            }
            
            self::$initialized = false;
            
            self::logSecurityEvent('session_destroyed', [
                'user_id' => $userId,
                'session_id' => substr($sessionId, 0, 10) . '...'
            ]);
            
            return true;
            
        } catch (Exception $e) {
            error_log('Session destruction failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Create user login session
     */
    public static function createUserSession(int $userId, array $userData, bool $rememberMe = false): bool {
        try {
            self::init();
            
            // Clear any existing session data
            self::clear();
            
            // Set user session data
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $userData['username'];
            $_SESSION['email'] = $userData['email'];
            $_SESSION['role'] = $userData['role'];
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['remember_me'] = $rememberMe;
            
            // Set session timeout
            $timeout = $rememberMe ? 
                time() + SecurityConfig::REMEMBER_ME_LIFETIME : 
                time() + SecurityConfig::SESSION_LIFETIME;
            $_SESSION['session_timeout'] = $timeout;
            
            // Store session in database
            self::storeSessionInDatabase($userId, $timeout);
            
            self::logSecurityEvent('user_session_created', [
                'user_id' => $userId,
                'username' => $userData['username'],
                'remember_me' => $rememberMe
            ]);
            
            return true;
            
        } catch (Exception $e) {
            error_log('User session creation failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user session is valid
     */
    public static function isValidUserSession(): array {
        self::init();
        
        // Check if user is logged in
        if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
            return ['valid' => false, 'reason' => 'not_logged_in'];
        }
        
        // Check required session data
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['username'])) {
            return ['valid' => false, 'reason' => 'incomplete_session'];
        }
        
        // Check session timeout
        if (isset($_SESSION['session_timeout']) && time() > $_SESSION['session_timeout']) {
            self::destroy();
            return ['valid' => false, 'reason' => 'session_expired'];
        }
        
        // Verify user still exists in database
        try {
            $userQuery = "SELECT id, username, is_active FROM users WHERE id = ?";
            $stmt = DatabaseConfig::executeQuery($userQuery, [$_SESSION['user_id']]);
            $user = $stmt->fetch();
            
            if (!$user || !$user['is_active']) {
                self::destroy();
                return ['valid' => false, 'reason' => 'user_inactive'];
            }
            
            return [
                'valid' => true,
                'user_id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'role' => $_SESSION['role'] ?? 'user'
            ];
            
        } catch (Exception $e) {
            return ['valid' => false, 'reason' => 'database_error'];
        }
    }
    
    /**
     * Get current user ID from session
     */
    public static function getCurrentUserId(): ?int {
        $session = self::isValidUserSession();
        return $session['valid'] ? $session['user_id'] : null;
    }
    
    /**
     * Check if user has specific role
     */
    public static function hasRole(string $role): bool {
        $session = self::isValidUserSession();
        if (!$session['valid']) {
            return false;
        }
        
        $userRole = $_SESSION['role'] ?? 'user';
        
        // Admin has all permissions
        if ($userRole === 'admin') {
            return true;
        }
        
        return $userRole === $role;
    }
    
    /**
     * Generate and store CSRF token
     */
    public static function generateCSRFToken(string $action = 'default'): string {
        self::init();
        
        $token = SecurityConfig::generateSecureToken(32);
        $expiry = time() + SecurityConfig::CSRF_TOKEN_EXPIRY;
        
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        $_SESSION['csrf_tokens'][$token] = [
            'action' => $action,
            'expiry' => $expiry,
            'created_at' => time()
        ];
        
        // Clean expired tokens
        self::cleanExpiredCSRFTokens();
        
        return $token;
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateCSRFToken(string $token, string $action = 'default'): bool {
        self::init();
        
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $tokenData = $_SESSION['csrf_tokens'][$token];
        
        // Check expiry
        if (time() > $tokenData['expiry']) {
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }
        
        // Check action
        if ($tokenData['action'] !== $action) {
            return false;
        }
        
        // Remove token (one-time use)
        unset($_SESSION['csrf_tokens'][$token]);
        
        return true;
    }
    
    /**
     * Clean expired CSRF tokens
     */
    private static function cleanExpiredCSRFTokens(): void {
        if (!isset($_SESSION['csrf_tokens'])) {
            return;
        }
        
        $currentTime = time();
        foreach ($_SESSION['csrf_tokens'] as $token => $data) {
            if ($currentTime > $data['expiry']) {
                unset($_SESSION['csrf_tokens'][$token]);
            }
        }
    }
    
    /**
     * Store session in database
     */
    private static function storeSessionInDatabase(int $userId, int $expiresAt): void {
        $query = "
            INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                last_activity = CURRENT_TIMESTAMP,
                expires_at = VALUES(expires_at)
        ";
        
        DatabaseConfig::executeQuery($query, [
            $userId,
            session_id(),
            SecurityConfig::getClientIP(),
            SecurityConfig::getUserAgent(),
            date('Y-m-d H:i:s', $expiresAt)
        ]);
    }
    
    /**
     * Update session ID in database
     */
    private static function updateSessionInDatabase(string $oldSessionId, string $newSessionId): void {
        $query = "UPDATE user_sessions SET session_id = ? WHERE session_id = ?";
        DatabaseConfig::executeQuery($query, [$newSessionId, $oldSessionId]);
    }
    
    /**
     * Remove session from database
     */
    private static function removeSessionFromDatabase(int $userId, string $sessionId): void {
        $query = "DELETE FROM user_sessions WHERE user_id = ? AND session_id = ?";
        DatabaseConfig::executeQuery($query, [$userId, $sessionId]);
    }
    
    /**
     * Load additional session data
     */
    private static function loadSessionData(): void {
        // Load user preferences, settings, etc.
        $userId = self::getCurrentUserId();
        if ($userId) {
            try {
                $query = "SELECT preference_key, preference_value FROM user_preferences WHERE user_id = ?";
                $stmt = DatabaseConfig::executeQuery($query, [$userId]);
                $preferences = $stmt->fetchAll();
                
                $_SESSION['preferences'] = [];
                foreach ($preferences as $pref) {
                    $_SESSION['preferences'][$pref['preference_key']] = $pref['preference_value'];
                }
                
            } catch (Exception $e) {
                // Preferences loading is not critical
                error_log('Failed to load user preferences: ' . $e->getMessage());
            }
        }
    }
    
    /**
     * Get session statistics
     */
    public static function getSessionStats(): array {
        self::init();
        
        return [
            'session_id' => session_id(),
            'created_at' => $_SESSION['created_at'] ?? null,
            'last_activity' => $_SESSION['last_activity'] ?? null,
            'last_regeneration' => $_SESSION['last_regeneration'] ?? null,
            'ip_address' => $_SESSION['ip_address'] ?? null,
            'user_agent' => $_SESSION['user_agent'] ?? null,
            'logged_in' => $_SESSION['logged_in'] ?? false,
            'user_id' => $_SESSION['user_id'] ?? null,
            'csrf_tokens_count' => count($_SESSION['csrf_tokens'] ?? [])
        ];
    }
    
    /**
     * Clean up all expired sessions
     */
    public static function cleanupExpiredSessions(): int {
        try {
            $query = "DELETE FROM user_sessions WHERE expires_at < NOW()";
            $stmt = DatabaseConfig::executeQuery($query);
            return $stmt->rowCount();
            
        } catch (Exception $e) {
            error_log('Session cleanup failed: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Get active sessions for user
     */
    public static function getUserActiveSessions(int $userId): array {
        try {
            $query = "
                SELECT session_id, ip_address, user_agent, created_at, last_activity, expires_at
                FROM user_sessions 
                WHERE user_id = ? AND expires_at > NOW()
                ORDER BY last_activity DESC
            ";
            $stmt = DatabaseConfig::executeQuery($query, [$userId]);
            return $stmt->fetchAll();
            
        } catch (Exception $e) {
            return [];
        }
    }
    
    /**
     * Terminate specific user session
     */
    public static function terminateUserSession(int $userId, string $sessionId): bool {
        try {
            $query = "DELETE FROM user_sessions WHERE user_id = ? AND session_id = ?";
            $stmt = DatabaseConfig::executeQuery($query, [$userId, $sessionId]);
            return $stmt->rowCount() > 0;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Terminate all user sessions except current
     */
    public static function terminateOtherUserSessions(int $userId): int {
        try {
            $currentSessionId = session_id();
            $query = "DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?";
            $stmt = DatabaseConfig::executeQuery($query, [$userId, $currentSessionId]);
            return $stmt->rowCount();
            
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Log security event
     */
    private static function logSecurityEvent(string $event, array $details = []): void {
        SecurityConfig::logSecurityEvent($event, $details);
    }
}

// Initialize session when this file is included
SessionManager::init();

?>