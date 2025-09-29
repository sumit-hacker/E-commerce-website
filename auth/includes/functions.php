<?php
/**
 * Core Authentication Functions
 * 
 * Comprehensive authentication helper functions including registration,
 * login, password reset, email verification, and user management.
 * 
 * @author Sumit
 * @version 1.0
 */

// Define AUTH_SYSTEM constant to allow config files to load
define('AUTH_SYSTEM', true);

// Include required configuration files
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/email.php';
require_once __DIR__ . '/../config/security.php';

class AuthFunctions {
    
    /**
     * Register a new user
     * 
     * @param array $userData
     * @return array
     */
    public static function registerUser(array $userData): array {
        try {
            // Validate input data
            $validation = self::validateRegistrationData($userData);
            if (!$validation['valid']) {
                return ['success' => false, 'errors' => $validation['errors']];
            }
            
            $username = SecurityConfig::sanitizeInput($userData['username']);
            $email = strtolower(trim($userData['email']));
            $password = $userData['password'];
            $firstName = SecurityConfig::sanitizeInput($userData['first_name'] ?? '');
            $lastName = SecurityConfig::sanitizeInput($userData['last_name'] ?? '');
            $phone = SecurityConfig::sanitizeInput($userData['phone'] ?? '');
            
            // Check if user already exists
            if (self::userExists($username, $email)) {
                return ['success' => false, 'errors' => ['Username or email already exists']];
            }
            
            // Hash password
            $passwordHash = SecurityConfig::hashPassword($password);
            
            // Generate verification token
            $verificationToken = SecurityConfig::generateSecureToken();
            $verificationExpiry = date('Y-m-d H:i:s', time() + SecurityConfig::VERIFICATION_TOKEN_EXPIRY);
            
            // Start database transaction
            DatabaseConfig::beginTransaction();
            
            try {
                // Insert user
                $userQuery = "
                    INSERT INTO users (username, email, password_hash, first_name, last_name, phone, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                ";
                $userStmt = DatabaseConfig::executeQuery($userQuery, [
                    $username, $email, $passwordHash, $firstName, $lastName, $phone
                ]);
                
                $userId = DatabaseConfig::getLastInsertId();
                
                // Insert verification token
                $tokenQuery = "
                    INSERT INTO email_verification_tokens (user_id, token, expires_at) 
                    VALUES (?, ?, ?)
                ";
                DatabaseConfig::executeQuery($tokenQuery, [$userId, $verificationToken, $verificationExpiry]);
                
                // Commit transaction
                DatabaseConfig::commit();
                
                // Send verification email
                $emailResult = EmailConfig::sendVerificationEmail($email, $username, $verificationToken);
                
                // Log registration event
                self::logSecurityEvent('registration', [
                    'user_id' => $userId,
                    'username' => $username,
                    'email' => $email,
                    'email_sent' => $emailResult['success']
                ]);
                
                if (!$emailResult['success']) {
                    return [
                        'success' => true,
                        'message' => 'Account created successfully, but verification email could not be sent. Please contact support.',
                        'user_id' => $userId
                    ];
                }
                
                return [
                    'success' => true,
                    'message' => 'Account created successfully. Please check your email to verify your account.',
                    'user_id' => $userId
                ];
                
            } catch (Exception $e) {
                DatabaseConfig::rollback();
                throw $e;
            }
            
        } catch (Exception $e) {
            self::logSecurityEvent('registration_error', [
                'error' => $e->getMessage(),
                'username' => $userData['username'] ?? '',
                'email' => $userData['email'] ?? ''
            ]);
            
            return ['success' => false, 'errors' => ['Registration failed. Please try again.']];
        }
    }
    
    /**
     * Authenticate user login
     * 
     * @param string $usernameOrEmail
     * @param string $password
     * @param bool $rememberMe
     * @return array
     */
    public static function loginUser(string $usernameOrEmail, string $password, bool $rememberMe = false): array {
        try {
            $identifier = strtolower(trim($usernameOrEmail));
            
            // Check rate limiting
            $rateLimit = SecurityConfig::checkRateLimit('login', $identifier);
            if (!$rateLimit['allowed']) {
                return ['success' => false, 'errors' => [$rateLimit['message']]];
            }
            
            // Find user by username or email
            $user = self::getUserByUsernameOrEmail($identifier);
            
            if (!$user) {
                SecurityConfig::recordAttempt('login', $identifier);
                self::logSecurityEvent('login_failed', [
                    'identifier' => $identifier,
                    'reason' => 'user_not_found'
                ]);
                return ['success' => false, 'errors' => ['Invalid username/email or password']];
            }
            
            // Check if account is locked
            if (self::isAccountLocked($user['id'])) {
                self::logSecurityEvent('login_failed', [
                    'user_id' => $user['id'],
                    'reason' => 'account_locked'
                ]);
                return ['success' => false, 'errors' => ['Account is temporarily locked. Please try again later.']];
            }
            
            // Verify password
            if (!SecurityConfig::verifyPassword($password, $user['password_hash'])) {
                self::recordFailedLogin($user['id']);
                SecurityConfig::recordAttempt('login', $identifier);
                self::logSecurityEvent('login_failed', [
                    'user_id' => $user['id'],
                    'reason' => 'invalid_password'
                ]);
                return ['success' => false, 'errors' => ['Invalid username/email or password']];
            }
            
            // Check if account is active
            if (!$user['is_active']) {
                self::logSecurityEvent('login_failed', [
                    'user_id' => $user['id'],
                    'reason' => 'account_inactive'
                ]);
                return ['success' => false, 'errors' => ['Account is inactive. Please contact support.']];
            }
            
            // Check if email is verified
            if (!$user['is_verified']) {
                return [
                    'success' => false, 
                    'errors' => ['Please verify your email address before logging in.'],
                    'needs_verification' => true,
                    'user_id' => $user['id']
                ];
            }
            
            // Check if password needs rehashing
            if (SecurityConfig::needsRehash($user['password_hash'])) {
                $newHash = SecurityConfig::hashPassword($password);
                self::updateUserPassword($user['id'], $newHash);
            }
            
            // Reset failed login attempts
            self::resetFailedLogins($user['id']);
            
            // Create user session
            $sessionResult = self::createUserSession($user, $rememberMe);
            
            if (!$sessionResult['success']) {
                return ['success' => false, 'errors' => ['Failed to create session. Please try again.']];
            }
            
            // Update last login
            self::updateLastLogin($user['id']);
            
            // Log successful login
            self::logSecurityEvent('login_success', [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'remember_me' => $rememberMe
            ]);
            
            return [
                'success' => true,
                'message' => 'Login successful',
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'first_name' => $user['first_name'],
                    'last_name' => $user['last_name'],
                    'role' => $user['role']
                ]
            ];
            
        } catch (Exception $e) {
            self::logSecurityEvent('login_error', [
                'error' => $e->getMessage(),
                'identifier' => $usernameOrEmail
            ]);
            
            return ['success' => false, 'errors' => ['Login failed. Please try again.']];
        }
    }
    
    /**
     * Verify email with token
     * 
     * @param string $token
     * @return array
     */
    public static function verifyEmail(string $token): array {
        try {
            // Find verification token
            $tokenQuery = "
                SELECT evt.*, u.username, u.email 
                FROM email_verification_tokens evt
                JOIN users u ON evt.user_id = u.id
                WHERE evt.token = ? AND evt.used_at IS NULL AND evt.expires_at > NOW()
            ";
            $tokenStmt = DatabaseConfig::executeQuery($tokenQuery, [$token]);
            $tokenData = $tokenStmt->fetch();
            
            if (!$tokenData) {
                return ['success' => false, 'errors' => ['Invalid or expired verification token']];
            }
            
            // Start transaction
            DatabaseConfig::beginTransaction();
            
            try {
                // Mark user as verified
                $updateUserQuery = "UPDATE users SET is_verified = 1 WHERE id = ?";
                DatabaseConfig::executeQuery($updateUserQuery, [$tokenData['user_id']]);
                
                // Mark token as used
                $updateTokenQuery = "UPDATE email_verification_tokens SET used_at = NOW() WHERE id = ?";
                DatabaseConfig::executeQuery($updateTokenQuery, [$tokenData['id']]);
                
                DatabaseConfig::commit();
                
                // Log verification event
                self::logSecurityEvent('email_verification', [
                    'user_id' => $tokenData['user_id'],
                    'username' => $tokenData['username'],
                    'email' => $tokenData['email']
                ]);
                
                return [
                    'success' => true,
                    'message' => 'Email verified successfully. You can now log in.',
                    'user_id' => $tokenData['user_id']
                ];
                
            } catch (Exception $e) {
                DatabaseConfig::rollback();
                throw $e;
            }
            
        } catch (Exception $e) {
            self::logSecurityEvent('verification_error', [
                'error' => $e->getMessage(),
                'token' => substr($token, 0, 10) . '...'
            ]);
            
            return ['success' => false, 'errors' => ['Email verification failed. Please try again.']];
        }
    }
    
    /**
     * Request password reset
     * 
     * @param string $email
     * @return array
     */
    public static function requestPasswordReset(string $email): array {
        try {
            $email = strtolower(trim($email));
            
            // Check rate limiting
            $rateLimit = SecurityConfig::checkRateLimit('password_reset', $email);
            if (!$rateLimit['allowed']) {
                return ['success' => false, 'errors' => [$rateLimit['message']]];
            }
            
            // Find user by email
            $userQuery = "SELECT id, username, email FROM users WHERE email = ? AND is_active = 1";
            $userStmt = DatabaseConfig::executeQuery($userQuery, [$email]);
            $user = $userStmt->fetch();
            
            // Always return success to prevent email enumeration
            $successMessage = 'If an account with that email exists, you will receive a password reset email shortly.';
            
            if (!$user) {
                SecurityConfig::recordAttempt('password_reset', $email);
                self::logSecurityEvent('password_reset_failed', [
                    'email' => $email,
                    'reason' => 'user_not_found'
                ]);
                return ['success' => true, 'message' => $successMessage];
            }
            
            // Generate reset token
            $resetToken = SecurityConfig::generateSecureToken();
            $resetExpiry = date('Y-m-d H:i:s', time() + SecurityConfig::RESET_TOKEN_EXPIRY);
            
            // Store reset token
            $tokenQuery = "
                INSERT INTO password_reset_tokens (user_id, token, expires_at, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)
            ";
            DatabaseConfig::executeQuery($tokenQuery, [
                $user['id'],
                $resetToken,
                $resetExpiry,
                SecurityConfig::getClientIP(),
                SecurityConfig::getUserAgent()
            ]);
            
            // Send reset email
            $emailResult = EmailConfig::sendPasswordResetEmail($user['email'], $user['username'], $resetToken);
            
            SecurityConfig::recordAttempt('password_reset', $email);
            
            // Log password reset request
            self::logSecurityEvent('password_reset_requested', [
                'user_id' => $user['id'],
                'email' => $email,
                'email_sent' => $emailResult['success']
            ]);
            
            return ['success' => true, 'message' => $successMessage];
            
        } catch (Exception $e) {
            self::logSecurityEvent('password_reset_error', [
                'error' => $e->getMessage(),
                'email' => $email
            ]);
            
            return ['success' => false, 'errors' => ['Password reset request failed. Please try again.']];
        }
    }
    
    /**
     * Reset password with token
     * 
     * @param string $token
     * @param string $newPassword
     * @return array
     */
    public static function resetPassword(string $token, string $newPassword): array {
        try {
            // Validate password
            $passwordValidation = SecurityConfig::validatePassword($newPassword);
            if (!$passwordValidation['valid']) {
                return ['success' => false, 'errors' => $passwordValidation['errors']];
            }
            
            // Find reset token
            $tokenQuery = "
                SELECT prt.*, u.username, u.email 
                FROM password_reset_tokens prt
                JOIN users u ON prt.user_id = u.id
                WHERE prt.token = ? AND prt.used_at IS NULL AND prt.expires_at > NOW()
            ";
            $tokenStmt = DatabaseConfig::executeQuery($tokenQuery, [$token]);
            $tokenData = $tokenStmt->fetch();
            
            if (!$tokenData) {
                return ['success' => false, 'errors' => ['Invalid or expired reset token']];
            }
            
            // Hash new password
            $passwordHash = SecurityConfig::hashPassword($newPassword);
            
            // Start transaction
            DatabaseConfig::beginTransaction();
            
            try {
                // Update user password
                $updatePasswordQuery = "UPDATE users SET password_hash = ?, login_attempts = 0, lockout_time = NULL WHERE id = ?";
                DatabaseConfig::executeQuery($updatePasswordQuery, [$passwordHash, $tokenData['user_id']]);
                
                // Mark token as used
                $updateTokenQuery = "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = ?";
                DatabaseConfig::executeQuery($updateTokenQuery, [$tokenData['id']]);
                
                // Invalidate all other reset tokens for this user
                $invalidateTokensQuery = "
                    UPDATE password_reset_tokens 
                    SET used_at = NOW() 
                    WHERE user_id = ? AND id != ? AND used_at IS NULL
                ";
                DatabaseConfig::executeQuery($invalidateTokensQuery, [$tokenData['user_id'], $tokenData['id']]);
                
                DatabaseConfig::commit();
                
                // Log password reset
                self::logSecurityEvent('password_reset', [
                    'user_id' => $tokenData['user_id'],
                    'username' => $tokenData['username'],
                    'email' => $tokenData['email']
                ]);
                
                return [
                    'success' => true,
                    'message' => 'Password reset successfully. You can now log in with your new password.',
                    'user_id' => $tokenData['user_id']
                ];
                
            } catch (Exception $e) {
                DatabaseConfig::rollback();
                throw $e;
            }
            
        } catch (Exception $e) {
            self::logSecurityEvent('password_reset_error', [
                'error' => $e->getMessage(),
                'token' => substr($token, 0, 10) . '...'
            ]);
            
            return ['success' => false, 'errors' => ['Password reset failed. Please try again.']];
        }
    }
    
    /**
     * Logout user
     * 
     * @return array
     */
    public static function logoutUser(): array {
        try {
            $userId = $_SESSION['user_id'] ?? null;
            
            if ($userId) {
                // Remove user session from database
                $sessionQuery = "DELETE FROM user_sessions WHERE user_id = ? AND session_id = ?";
                DatabaseConfig::executeQuery($sessionQuery, [$userId, session_id()]);
                
                // Log logout event
                self::logSecurityEvent('logout', ['user_id' => $userId]);
            }
            
            // Destroy session
            SecurityConfig::destroySession();
            
            return ['success' => true, 'message' => 'Logged out successfully'];
            
        } catch (Exception $e) {
            self::logSecurityEvent('logout_error', [
                'error' => $e->getMessage(),
                'user_id' => $_SESSION['user_id'] ?? null
            ]);
            
            // Still destroy session even if database operation fails
            SecurityConfig::destroySession();
            
            return ['success' => true, 'message' => 'Logged out successfully'];
        }
    }
    
    /**
     * Check if user is logged in
     * 
     * @return array
     */
    public static function isLoggedIn(): array {
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['logged_in'])) {
            return ['logged_in' => false];
        }
        
        // Check session timeout
        if (isset($_SESSION['session_timeout']) && time() > $_SESSION['session_timeout']) {
            SecurityConfig::destroySession();
            return ['logged_in' => false, 'reason' => 'session_expired'];
        }
        
        // Verify user still exists and is active
        try {
            $userQuery = "SELECT id, username, email, first_name, last_name, role, is_active FROM users WHERE id = ? AND is_active = 1";
            $userStmt = DatabaseConfig::executeQuery($userQuery, [$_SESSION['user_id']]);
            $user = $userStmt->fetch();
            
            if (!$user) {
                SecurityConfig::destroySession();
                return ['logged_in' => false, 'reason' => 'user_inactive'];
            }
            
            return [
                'logged_in' => true,
                'user' => $user
            ];
            
        } catch (Exception $e) {
            return ['logged_in' => false, 'reason' => 'database_error'];
        }
    }
    
    /**
     * Get current user information
     * 
     * @return array|null
     */
    public static function getCurrentUser(): ?array {
        $loginCheck = self::isLoggedIn();
        return $loginCheck['logged_in'] ? $loginCheck['user'] : null;
    }
    
    // ========== HELPER FUNCTIONS ==========
    
    /**
     * Validate registration data
     * 
     * @param array $data
     * @return array
     */
    private static function validateRegistrationData(array $data): array {
        $errors = [];
        
        // Required fields
        $requiredFields = ['username', 'email', 'password'];
        foreach ($requiredFields as $field) {
            if (empty($data[$field])) {
                $errors[] = ucfirst($field) . ' is required';
            }
        }
        
        if (!empty($errors)) {
            return ['valid' => false, 'errors' => $errors];
        }
        
        // Validate username
        $usernameValidation = SecurityConfig::validateInput($data['username'], 'username');
        if (!$usernameValidation['valid']) {
            $errors = array_merge($errors, $usernameValidation['errors']);
        }
        
        // Validate email
        $emailValidation = SecurityConfig::validateInput($data['email'], 'email');
        if (!$emailValidation['valid']) {
            $errors = array_merge($errors, $emailValidation['errors']);
        }
        
        // Validate password
        $passwordValidation = SecurityConfig::validatePassword($data['password']);
        if (!$passwordValidation['valid']) {
            $errors = array_merge($errors, $passwordValidation['errors']);
        }
        
        // Validate optional fields
        if (!empty($data['first_name'])) {
            $nameValidation = SecurityConfig::validateInput($data['first_name'], 'name');
            if (!$nameValidation['valid']) {
                $errors = array_merge($errors, $nameValidation['errors']);
            }
        }
        
        if (!empty($data['last_name'])) {
            $nameValidation = SecurityConfig::validateInput($data['last_name'], 'name');
            if (!$nameValidation['valid']) {
                $errors = array_merge($errors, $nameValidation['errors']);
            }
        }
        
        if (!empty($data['phone'])) {
            $phoneValidation = SecurityConfig::validateInput($data['phone'], 'phone');
            if (!$phoneValidation['valid']) {
                $errors = array_merge($errors, $phoneValidation['errors']);
            }
        }
        
        return ['valid' => empty($errors), 'errors' => $errors];
    }
    
    /**
     * Check if user exists
     * 
     * @param string $username
     * @param string $email
     * @return bool
     */
    private static function userExists(string $username, string $email): bool {
        $query = "SELECT id FROM users WHERE username = ? OR email = ?";
        $stmt = DatabaseConfig::executeQuery($query, [$username, $email]);
        return $stmt->fetch() !== false;
    }
    
    /**
     * Get user by username or email
     * 
     * @param string $identifier
     * @return array|false
     */
    private static function getUserByUsernameOrEmail(string $identifier) {
        $query = "
            SELECT id, username, email, password_hash, first_name, last_name, 
                   is_verified, is_active, role, login_attempts, lockout_time
            FROM users 
            WHERE (username = ? OR email = ?) AND is_active = 1
        ";
        $stmt = DatabaseConfig::executeQuery($query, [$identifier, $identifier]);
        return $stmt->fetch();
    }
    
    /**
     * Check if account is locked
     * 
     * @param int $userId
     * @return bool
     */
    private static function isAccountLocked(int $userId): bool {
        $query = "SELECT login_attempts, lockout_time FROM users WHERE id = ?";
        $stmt = DatabaseConfig::executeQuery($query, [$userId]);
        $user = $stmt->fetch();
        
        if (!$user) return false;
        
        if ($user['login_attempts'] >= SecurityConfig::LOGIN_MAX_ATTEMPTS) {
            if ($user['lockout_time'] && strtotime($user['lockout_time']) > time()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Record failed login attempt
     * 
     * @param int $userId
     */
    private static function recordFailedLogin(int $userId): void {
        $lockoutTime = date('Y-m-d H:i:s', time() + SecurityConfig::LOGIN_LOCKOUT_TIME);
        $query = "
            UPDATE users 
            SET login_attempts = login_attempts + 1, 
                lockout_time = CASE 
                    WHEN login_attempts + 1 >= ? THEN ? 
                    ELSE lockout_time 
                END
            WHERE id = ?
        ";
        DatabaseConfig::executeQuery($query, [SecurityConfig::LOGIN_MAX_ATTEMPTS, $lockoutTime, $userId]);
    }
    
    /**
     * Reset failed login attempts
     * 
     * @param int $userId
     */
    private static function resetFailedLogins(int $userId): void {
        $query = "UPDATE users SET login_attempts = 0, lockout_time = NULL WHERE id = ?";
        DatabaseConfig::executeQuery($query, [$userId]);
    }
    
    /**
     * Update user password
     * 
     * @param int $userId
     * @param string $passwordHash
     */
    private static function updateUserPassword(int $userId, string $passwordHash): void {
        $query = "UPDATE users SET password_hash = ? WHERE id = ?";
        DatabaseConfig::executeQuery($query, [$passwordHash, $userId]);
    }
    
    /**
     * Create user session
     * 
     * @param array $user
     * @param bool $rememberMe
     * @return array
     */
    private static function createUserSession(array $user, bool $rememberMe = false): array {
        try {
            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            
            // Set session timeout
            $sessionTimeout = $rememberMe ? 
                time() + SecurityConfig::REMEMBER_ME_LIFETIME : 
                time() + SecurityConfig::SESSION_LIFETIME;
            $_SESSION['session_timeout'] = $sessionTimeout;
            
            // Store session in database
            $sessionQuery = "
                INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    last_activity = CURRENT_TIMESTAMP,
                    expires_at = VALUES(expires_at)
            ";
            DatabaseConfig::executeQuery($sessionQuery, [
                $user['id'],
                session_id(),
                SecurityConfig::getClientIP(),
                SecurityConfig::getUserAgent(),
                date('Y-m-d H:i:s', $sessionTimeout)
            ]);
            
            return ['success' => true];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Update last login time
     * 
     * @param int $userId
     */
    private static function updateLastLogin(int $userId): void {
        $query = "UPDATE users SET last_login = NOW() WHERE id = ?";
        DatabaseConfig::executeQuery($query, [$userId]);
    }
    
    /**
     * Log security event
     * 
     * @param string $eventType
     * @param array $details
     */
    private static function logSecurityEvent(string $eventType, array $details = []): void {
        try {
            $query = "
                INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details) 
                VALUES (?, ?, ?, ?, ?)
            ";
            DatabaseConfig::executeQuery($query, [
                $details['user_id'] ?? null,
                $eventType,
                SecurityConfig::getClientIP(),
                SecurityConfig::getUserAgent(),
                json_encode($details)
            ]);
        } catch (Exception $e) {
            // Fallback to error log if database logging fails
            error_log("Security Event Log Failed: " . $e->getMessage());
        }
        
        // Also log to SecurityConfig
        SecurityConfig::logSecurityEvent($eventType, $details);
    }
    
    // ========== ADMIN FUNCTIONS ==========
    
    /**
     * Get all users (admin only)
     * 
     * @param int $page
     * @param int $perPage
     * @param string $search
     * @return array
     */
    public static function getAllUsers(int $page = 1, int $perPage = 20, string $search = ''): array {
        try {
            $offset = ($page - 1) * $perPage;
            $searchParam = '%' . $search . '%';
            
            // Count total users
            $countQuery = "
                SELECT COUNT(*) as total 
                FROM users 
                WHERE (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
            ";
            $countStmt = DatabaseConfig::executeQuery($countQuery, [$searchParam, $searchParam, $searchParam, $searchParam]);
            $total = $countStmt->fetch()['total'];
            
            // Get users
            $usersQuery = "
                SELECT id, username, email, first_name, last_name, is_verified, is_active, role, 
                       created_at, last_login, login_attempts
                FROM users 
                WHERE (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ";
            $usersStmt = DatabaseConfig::executeQuery($usersQuery, [
                $searchParam, $searchParam, $searchParam, $searchParam, $perPage, $offset
            ]);
            $users = $usersStmt->fetchAll();
            
            return [
                'success' => true,
                'users' => $users,
                'pagination' => [
                    'current_page' => $page,
                    'per_page' => $perPage,
                    'total_items' => $total,
                    'total_pages' => ceil($total / $perPage)
                ]
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'Failed to fetch users'];
        }
    }
    
    /**
     * Update user status (admin only)
     * 
     * @param int $userId
     * @param bool $isActive
     * @return array
     */
    public static function updateUserStatus(int $userId, bool $isActive): array {
        try {
            $query = "UPDATE users SET is_active = ? WHERE id = ?";
            DatabaseConfig::executeQuery($query, [$isActive ? 1 : 0, $userId]);
            
            return ['success' => true, 'message' => 'User status updated successfully'];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => 'Failed to update user status'];
        }
    }
}

?>