<?php
/**
 * Password Reset Page
 * 
 * Handle password reset with token validation and security
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Reset Password - E-Commerce Authentication');

// Include required files
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/validation.php';
require_once __DIR__ . '/includes/session.php';

// Initialize session
SessionManager::init();

// Redirect if already logged in
$loginCheck = SessionManager::isValidUserSession();
if ($loginCheck['valid']) {
    header('Location: dashboard.php');
    exit;
}

$errors = [];
$success = false;
$message = '';
$validToken = false;
$token = '';

// Get token from URL
if (isset($_GET['token'])) {
    $token = trim($_GET['token']);
    
    if (!empty($token)) {
        // Validate token exists and is not expired
        $tokenQuery = "
            SELECT prt.id, prt.user_id, prt.expires_at, u.username, u.email 
            FROM password_reset_tokens prt
            JOIN users u ON prt.user_id = u.id
            WHERE prt.token = ? AND prt.used_at IS NULL AND prt.expires_at > NOW()
        ";
        
        try {
            $tokenStmt = DatabaseConfig::executeQuery($tokenQuery, [$token]);
            $tokenData = $tokenStmt->fetch();
            
            if ($tokenData) {
                $validToken = true;
            } else {
                $errors['general'] = ['Invalid or expired reset token. Please request a new password reset.'];
            }
        } catch (Exception $e) {
            $errors['general'] = ['Unable to validate reset token. Please try again.'];
        }
    } else {
        $errors['general'] = ['No reset token provided.'];
    }
} else {
    $errors['general'] = ['No reset token provided.'];
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $validToken) {
    try {
        // Validate CSRF token
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'reset_password')) {
            throw new Exception('Invalid security token. Please try again.');
        }
        
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        // Validate passwords
        if (empty($password)) {
            $errors['password'] = ['New password is required'];
        }
        
        if (empty($confirmPassword)) {
            $errors['confirm_password'] = ['Password confirmation is required'];
        }
        
        if (!empty($password) && !empty($confirmPassword)) {
            if ($password !== $confirmPassword) {
                $errors['confirm_password'] = ['Passwords do not match'];
            } else {
                // Validate password strength
                $passwordValidation = SecurityConfig::validatePassword($password);
                if (!$passwordValidation['valid']) {
                    $errors['password'] = $passwordValidation['errors'];
                }
            }
        }
        
        // If validation passed, reset password
        if (empty($errors)) {
            $resetResult = AuthFunctions::resetPassword($token, $password);
            
            if ($resetResult['success']) {
                $success = true;
                $message = $resetResult['message'];
                $validToken = false; // Prevent form from showing again
            } else {
                $errors['general'] = $resetResult['errors'];
            }
        }
        
        // If AJAX request, return JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => $success,
                'message' => $message,
                'errors' => $errors
            ]);
            exit;
        }
        
    } catch (Exception $e) {
        $errors['general'] = [$e->getMessage()];
        
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'errors' => ['general' => [$e->getMessage()]]
            ]);
            exit;
        }
    }
}

// Generate CSRF token for the form
$csrfToken = SecurityConfig::generateCSRFToken('reset_password');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Set a new password for your e-commerce account with our secure password reset system.">
    <meta name="robots" content="noindex, nofollow">
    
    <!-- Stylesheets -->
    <link rel="stylesheet" href="css/auth.css">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    
    <!-- Preload critical resources -->
    <link rel="preload" href="js/auth.js" as="script">
</head>
<body>
    <div class="auth-container fade-in">
        <!-- Header -->
        <div class="auth-header">
            <span class="icon">🔑</span>
            <h1><?php echo $success ? 'Password Reset!' : 'Reset Password'; ?></h1>
            <p><?php echo $success ? 'Your password has been updated' : 'Create a new secure password'; ?></p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <?php if ($success): ?>
                <!-- Success State -->
                <div class="alert alert-success">
                    <strong>✅ Password Reset Successful!</strong><br>
                    <?php echo htmlspecialchars($message); ?>
                </div>
                
                <div class="text-center" style="margin: 30px 0;">
                    <div style="font-size: 4rem; margin-bottom: 20px;">🎉</div>
                    <h3>All Set!</h3>
                    <p>Your password has been successfully updated. You can now sign in with your new password.</p>
                </div>
                
                <div class="auth-links">
                    <a href="login.php" class="btn btn-primary btn-full">Sign In Now</a>
                    <p style="margin-top: 15px;"><a href="register.php">Create New Account</a></p>
                </div>
                
                <div class="alert alert-info" style="margin-top: 30px;">
                    <strong>🔒 Security Tips:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Your password has been securely encrypted</li>
                        <li>All existing sessions have been terminated</li>
                        <li>Consider enabling two-factor authentication</li>
                        <li>Use a password manager for better security</li>
                    </ul>
                </div>
                
            <?php elseif ($validToken): ?>
                <!-- Password Reset Form -->
                <div class="text-center" style="margin-bottom: 30px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">🔐</div>
                    <h3>Create New Password</h3>
                    <p>Enter a strong password to secure your account.</p>
                </div>
                
                <form method="POST" action="reset-password.php?token=<?php echo urlencode($token); ?>" class="auth-form" novalidate>
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    
                    <!-- Display general errors -->
                    <?php if (!empty($errors['general'])): ?>
                        <div class="alert alert-error">
                            <?php foreach ($errors['general'] as $error): ?>
                                <div><?php echo htmlspecialchars($error); ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <!-- New Password -->
                    <div class="form-group <?php echo !empty($errors['password']) ? 'has-error' : ''; ?>">
                        <label for="password">New Password *</label>
                        <div class="input-icon">
                            <input 
                                type="password" 
                                id="password" 
                                name="password" 
                                required 
                                data-validate="password"
                                placeholder="Enter your new password"
                                autocomplete="new-password"
                                minlength="8"
                                maxlength="128"
                                autofocus
                            >
                            <i>🔒</i>
                        </div>
                        <?php if (!empty($errors['password'])): ?>
                            <?php foreach ($errors['password'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Confirm Password -->
                    <div class="form-group <?php echo !empty($errors['confirm_password']) ? 'has-error' : ''; ?>">
                        <label for="confirm_password">Confirm New Password *</label>
                        <div class="input-icon">
                            <input 
                                type="password" 
                                id="confirm_password" 
                                name="confirm_password" 
                                required 
                                placeholder="Confirm your new password"
                                autocomplete="new-password"
                                minlength="8"
                                maxlength="128"
                            >
                            <i>🔒</i>
                        </div>
                        <?php if (!empty($errors['confirm_password'])): ?>
                            <?php foreach ($errors['confirm_password'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Submit Button -->
                    <button type="submit" class="btn btn-primary btn-full">
                        Update Password
                    </button>
                </form>
                
                <!-- Password Requirements -->
                <div class="alert alert-info" style="margin-top: 30px;">
                    <strong>🔒 Password Requirements:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>At least 8 characters long</li>
                        <li>Contains uppercase and lowercase letters</li>
                        <li>Contains at least one number</li>
                        <li>Contains at least one special character (@$!%*?&)</li>
                        <li>Cannot be a commonly used password</li>
                    </ul>
                </div>
                
                <!-- Security Information -->
                <div class="alert alert-warning" style="margin-top: 20px;">
                    <strong>⏰ Time Limit:</strong><br>
                    This password reset link will expire in 15 minutes for security. 
                    If it expires, you'll need to request a new password reset.
                </div>
                
            <?php else: ?>
                <!-- Invalid Token State -->
                <div class="text-center" style="margin-bottom: 30px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">❌</div>
                    <h3>Invalid Reset Link</h3>
                    <p>This password reset link is invalid or has expired.</p>
                </div>
                
                <!-- Display general errors -->
                <?php if (!empty($errors['general'])): ?>
                    <div class="alert alert-error">
                        <?php foreach ($errors['general'] as $error): ?>
                            <div><?php echo htmlspecialchars($error); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <div class="alert alert-warning">
                    <strong>⚠️ Possible Reasons:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>The reset link has expired (links expire after 15 minutes)</li>
                        <li>The reset link has already been used</li>
                        <li>The reset link is malformed or incomplete</li>
                        <li>A newer reset link was requested</li>
                    </ul>
                </div>
                
                <div class="auth-links">
                    <a href="forgot-password.php" class="btn btn-primary btn-full">Request New Password Reset</a>
                    <p style="margin-top: 15px;"><a href="login.php">← Back to Login</a></p>
                    <p><a href="register.php">Create New Account</a></p>
                </div>
            <?php endif; ?>
            
            <!-- Additional Links -->
            <div class="auth-links" style="border-top: 1px solid #e1e5e9; margin-top: 30px; padding-top: 20px;">
                <?php if (!$success): ?>
                    <p><a href="login.php">← Back to Login</a></p>
                    <p><a href="forgot-password.php">Request New Reset Link</a></p>
                <?php endif; ?>
                <p><a href="/contact">Contact Support</a></p>
            </div>
        </div>
    </div>
    
    <!-- Loading overlay -->
    <div class="loading-overlay">
        <div class="loading-spinner"></div>
    </div>
    
    <!-- JavaScript -->
    <script src="js/auth.js"></script>
    
    <!-- Additional page-specific JavaScript -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-focus on password input if form is visible
            const passwordInput = document.querySelector('input[name="password"]');
            if (passwordInput && passwordInput.offsetParent !== null) {
                passwordInput.focus();
            }
            
            // Handle form submission with enhanced feedback
            const form = document.querySelector('.auth-form');
            if (form) {
                form.addEventListener('submit', function(e) {
                    const submitButton = form.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.textContent = 'Updating Password...';
                    }
                });
                
                // Real-time password confirmation validation
                const confirmPasswordInput = document.querySelector('input[name="confirm_password"]');
                if (confirmPasswordInput) {
                    confirmPasswordInput.addEventListener('input', function() {
                        const formGroup = this.closest('.form-group');
                        const password = passwordInput.value;
                        const confirmPassword = this.value;
                        
                        // Clear previous validation
                        formGroup.classList.remove('has-error', 'has-success');
                        const errorMessages = formGroup.querySelectorAll('.error-message.match-error');
                        errorMessages.forEach(msg => msg.remove());
                        
                        if (confirmPassword) {
                            if (password === confirmPassword) {
                                formGroup.classList.add('has-success');
                            } else {
                                formGroup.classList.add('has-error');
                                const errorMsg = document.createElement('span');
                                errorMsg.className = 'error-message match-error';
                                errorMsg.textContent = 'Passwords do not match';
                                formGroup.appendChild(errorMsg);
                            }
                        }
                    });
                }
            }
            
            // Auto-redirect after successful password reset
            <?php if ($success): ?>
            let countdown = 10;
            const updateCountdown = () => {
                const loginButton = document.querySelector('a[href="login.php"]');
                if (loginButton && countdown > 0) {
                    const originalText = loginButton.textContent.replace(/ \(\d+\)/, '');
                    loginButton.textContent = `${originalText} (${countdown})`;
                    countdown--;
                    setTimeout(updateCountdown, 1000);
                } else if (loginButton) {
                    window.location.href = 'login.php';
                }
            };
            setTimeout(updateCountdown, 3000);
            <?php endif; ?>
            
            // Token expiration countdown
            <?php if ($validToken && isset($tokenData)): ?>
            const expirationTime = new Date('<?php echo $tokenData['expires_at']; ?>').getTime();
            
            const updateExpiration = () => {
                const now = new Date().getTime();
                const timeLeft = expirationTime - now;
                
                if (timeLeft > 0) {
                    const minutes = Math.floor(timeLeft / (1000 * 60));
                    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
                    
                    let warningDiv = document.querySelector('.expiration-warning');
                    if (!warningDiv) {
                        warningDiv = document.createElement('div');
                        warningDiv.className = 'alert alert-warning expiration-warning';
                        const form = document.querySelector('.auth-form');
                        if (form) {
                            form.parentNode.insertBefore(warningDiv, form);
                        }
                    }
                    
                    const timeDisplay = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                    warningDiv.innerHTML = `
                        <strong>⏰ Time Remaining:</strong> ${timeDisplay}<br>
                        This reset link will expire soon. Please complete the password reset now.
                    `;
                    
                    // Change to danger alert when less than 2 minutes remain
                    if (timeLeft < 120000) {
                        warningDiv.className = 'alert alert-danger expiration-warning';
                    }
                    
                    setTimeout(updateExpiration, 1000);
                } else {
                    // Token expired, redirect to forgot password
                    window.location.href = 'forgot-password.php';
                }
            };
            
            updateExpiration();
            <?php endif; ?>
            
            // Add keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // ESC key to go back to login
                if (e.key === 'Escape') {
                    window.location.href = 'login.php';
                }
                
                // Tab navigation between password fields
                if (e.key === 'Tab' && e.target === passwordInput) {
                    if (!e.shiftKey && confirmPasswordInput) {
                        e.preventDefault();
                        confirmPasswordInput.focus();
                    }
                }
            });
            
            // Password generator feature
            const passwordInput = document.querySelector('input[name="password"]');
            if (passwordInput) {
                const generateButton = document.createElement('button');
                generateButton.type = 'button';
                generateButton.className = 'btn btn-outline';
                generateButton.style.cssText = 'font-size: 0.85rem; padding: 8px 15px; margin-top: 10px;';
                generateButton.textContent = '🎲 Generate Strong Password';
                generateButton.addEventListener('click', function() {
                    const strongPassword = window.AuthUtils.generatePassword(16);
                    passwordInput.value = strongPassword;
                    if (confirmPasswordInput) {
                        confirmPasswordInput.value = strongPassword;
                    }
                    
                    // Trigger validation events
                    passwordInput.dispatchEvent(new Event('input'));
                    if (confirmPasswordInput) {
                        confirmPasswordInput.dispatchEvent(new Event('input'));
                    }
                    
                    // Show password temporarily
                    const originalType = passwordInput.type;
                    passwordInput.type = 'text';
                    if (confirmPasswordInput) {
                        confirmPasswordInput.type = 'text';
                    }
                    
                    setTimeout(() => {
                        passwordInput.type = originalType;
                        if (confirmPasswordInput) {
                            confirmPasswordInput.type = originalType;
                        }
                    }, 3000);
                });
                
                const passwordGroup = passwordInput.closest('.form-group');
                if (passwordGroup) {
                    passwordGroup.appendChild(generateButton);
                }
            }
        });
    </script>
</body>
</html>