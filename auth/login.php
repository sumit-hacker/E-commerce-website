<?php
/**
 * User Login Page
 * 
 * Secure user login with rate limiting, session management,
 * and comprehensive security features.
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Login - E-Commerce Authentication');

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
$formData = [];
$showVerificationPrompt = false;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Validate CSRF token
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'login')) {
            throw new Exception('Invalid security token. Please try again.');
        }
        
        // Get form data
        $formData = [
            'username' => trim($_POST['username'] ?? ''),
            'password' => $_POST['password'] ?? '',
            'remember_me' => isset($_POST['remember_me'])
        ];
        
        // Basic validation
        if (empty($formData['username'])) {
            $errors['username'] = ['Username or email is required'];
        }
        
        if (empty($formData['password'])) {
            $errors['password'] = ['Password is required'];
        }
        
        // If basic validation passed, attempt login
        if (empty($errors)) {
            $loginResult = AuthFunctions::loginUser(
                $formData['username'], 
                $formData['password'], 
                $formData['remember_me']
            );
            
            if ($loginResult['success']) {
                $success = true;
                
                // Clear form data on success
                $formData = [];
                
                // Determine redirect URL
                $redirectUrl = $_GET['redirect'] ?? 'dashboard.php';
                
                // Validate redirect URL to prevent open redirect
                if (!preg_match('/^[a-zA-Z0-9\/_.-]+\.php(\?[a-zA-Z0-9=&_-]*)?$/', $redirectUrl)) {
                    $redirectUrl = 'dashboard.php';
                }
                
                // If AJAX request, return JSON
                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
                    header('Content-Type: application/json');
                    echo json_encode([
                        'success' => true,
                        'message' => $loginResult['message'],
                        'redirect' => $redirectUrl,
                        'user' => $loginResult['user']
                    ]);
                    exit;
                }
                
                // Redirect on successful login
                header('Location: ' . $redirectUrl);
                exit;
                
            } else {
                $errors['general'] = $loginResult['errors'];
                
                // Check if email verification is needed
                if (isset($loginResult['needs_verification']) && $loginResult['needs_verification']) {
                    $showVerificationPrompt = true;
                }
            }
        }
        
        // If AJAX request, return JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'errors' => $errors,
                'needs_verification' => $showVerificationPrompt
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
$csrfToken = SecurityConfig::generateCSRFToken('login');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Secure login to your e-commerce account with advanced authentication and security features.">
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
            <h1>Welcome Back</h1>
            <p>Sign in to your account</p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <!-- Login Form -->
            <form method="POST" action="login.php<?php echo !empty($_GET['redirect']) ? '?redirect=' . urlencode($_GET['redirect']) : ''; ?>" class="auth-form" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                
                <!-- Display general errors -->
                <?php if (!empty($errors['general'])): ?>
                    <div class="alert alert-error">
                        <?php foreach ($errors['general'] as $error): ?>
                            <div><?php echo htmlspecialchars($error); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <!-- Verification prompt -->
                <?php if ($showVerificationPrompt): ?>
                    <div class="alert alert-warning">
                        <strong>Email Verification Required</strong><br>
                        Please verify your email address before logging in. 
                        <a href="verify.php">Resend verification email</a>
                    </div>
                <?php endif; ?>
                
                <!-- Username/Email -->
                <div class="form-group <?php echo !empty($errors['username']) ? 'has-error' : ''; ?>">
                    <label for="username">Username or Email *</label>
                    <div class="input-icon">
                        <input 
                            type="text" 
                            id="username" 
                            name="username" 
                            value="<?php echo htmlspecialchars($formData['username'] ?? ''); ?>"
                            required 
                            placeholder="Enter your username or email"
                            autocomplete="username"
                            maxlength="255"
                            autofocus
                        >
                        <i>👤</i>
                    </div>
                    <?php if (!empty($errors['username'])): ?>
                        <?php foreach ($errors['username'] as $error): ?>
                            <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
                
                <!-- Password -->
                <div class="form-group <?php echo !empty($errors['password']) ? 'has-error' : ''; ?>">
                    <label for="password">Password *</label>
                    <div class="input-icon">
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            required 
                            placeholder="Enter your password"
                            autocomplete="current-password"
                            maxlength="128"
                        >
                        <i>🔒</i>
                    </div>
                    <?php if (!empty($errors['password'])): ?>
                        <?php foreach ($errors['password'] as $error): ?>
                            <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
                
                <!-- Remember Me -->
                <div class="form-group">
                    <div class="checkbox-group">
                        <input 
                            type="checkbox" 
                            id="remember_me" 
                            name="remember_me" 
                            value="1"
                            <?php echo (!empty($formData['remember_me'])) ? 'checked' : ''; ?>
                        >
                        <label for="remember_me">Remember me for 30 days</label>
                    </div>
                </div>
                
                <!-- Submit Button -->
                <button type="submit" class="btn btn-primary btn-full">
                    Sign In
                </button>
            </form>
            
            <!-- Links -->
            <div class="auth-links">
                <p><a href="forgot-password.php">Forgot your password?</a></p>
                <p>Don't have an account? <a href="register.php">Create Account</a></p>
                <p><a href="verify.php">Resend Verification Email</a></p>
            </div>
            
            <!-- Security Information -->
            <div class="alert alert-info" style="margin-top: 30px; font-size: 0.9rem;">
                <strong>🔒 Security Notice:</strong><br>
                Your account will be temporarily locked after 5 failed login attempts for security reasons.
                All login attempts are monitored and logged.
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
            // Auto-focus on first empty input
            const usernameInput = document.querySelector('input[name="username"]');
            const passwordInput = document.querySelector('input[name="password"]');
            
            if (usernameInput && !usernameInput.value) {
                usernameInput.focus();
            } else if (passwordInput && !passwordInput.value) {
                passwordInput.focus();
            }
            
            // Handle form submission with enhanced feedback
            const form = document.querySelector('.auth-form');
            if (form) {
                form.addEventListener('submit', function(e) {
                    // Add visual feedback for login attempt
                    const submitButton = form.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.textContent = 'Signing In...';
                    }
                });
            }
            
            // Handle verification link click
            const verificationLink = document.querySelector('a[href="verify.php"]');
            if (verificationLink) {
                verificationLink.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Pre-fill email if available
                    const usernameValue = document.querySelector('input[name="username"]').value;
                    const redirectUrl = usernameValue && usernameValue.includes('@') 
                        ? `verify.php?email=${encodeURIComponent(usernameValue)}`
                        : 'verify.php';
                    
                    window.location.href = redirectUrl;
                });
            }
            
            // Auto-clear error messages on input change
            document.querySelectorAll('input').forEach(input => {
                input.addEventListener('input', function() {
                    const formGroup = this.closest('.form-group');
                    if (formGroup.classList.contains('has-error')) {
                        formGroup.classList.remove('has-error');
                        const errorMessages = formGroup.querySelectorAll('.error-message');
                        errorMessages.forEach(msg => {
                            msg.style.opacity = '0';
                            setTimeout(() => msg.remove(), 300);
                        });
                    }
                });
            });
            
            // Handle "Enter" key on username field
            usernameInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && this.value.trim()) {
                    passwordInput.focus();
                    e.preventDefault();
                }
            });
            
            // Enhanced security warnings
            let failedAttempts = parseInt(localStorage.getItem('loginFailedAttempts') || '0');
            if (failedAttempts >= 3) {
                const securityNotice = document.querySelector('.alert-info');
                if (securityNotice) {
                    securityNotice.className = 'alert alert-warning';
                    securityNotice.innerHTML = `
                        <strong>⚠️ Security Warning:</strong><br>
                        You have ${failedAttempts} failed login attempts. 
                        Your account will be locked after ${5 - failedAttempts} more failed attempts.
                    `;
                }
            }
            
            // Track failed attempts (client-side for UI feedback only)
            if (form) {
                form.addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    try {
                        const formData = new FormData(form);
                        const response = await fetch(form.action, {
                            method: 'POST',
                            body: formData,
                            headers: {
                                'X-Requested-With': 'XMLHttpRequest'
                            }
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            localStorage.removeItem('loginFailedAttempts');
                            window.location.href = result.redirect || 'dashboard.php';
                        } else {
                            failedAttempts++;
                            localStorage.setItem('loginFailedAttempts', failedAttempts.toString());
                            
                            // Show errors
                            if (result.errors) {
                                Object.keys(result.errors).forEach(field => {
                                    const fieldElement = form.querySelector(`[name="${field}"]`);
                                    if (fieldElement) {
                                        const formGroup = fieldElement.closest('.form-group');
                                        formGroup.classList.add('has-error');
                                        
                                        result.errors[field].forEach(error => {
                                            const errorElement = document.createElement('span');
                                            errorElement.className = 'error-message';
                                            errorElement.textContent = error;
                                            formGroup.appendChild(errorElement);
                                        });
                                    }
                                });
                            }
                            
                            // Handle verification prompt
                            if (result.needs_verification) {
                                const verificationAlert = document.createElement('div');
                                verificationAlert.className = 'alert alert-warning';
                                verificationAlert.innerHTML = `
                                    <strong>Email Verification Required</strong><br>
                                    Please verify your email address before logging in. 
                                    <a href="verify.php">Resend verification email</a>
                                `;
                                form.insertBefore(verificationAlert, form.firstChild);
                            }
                        }
                        
                    } catch (error) {
                        console.error('Login error:', error);
                        window.AuthUtils.showAlert('An error occurred. Please try again.', 'error');
                    } finally {
                        // Reset button text
                        const submitButton = form.querySelector('button[type="submit"]');
                        if (submitButton) {
                            submitButton.textContent = 'Sign In';
                            submitButton.classList.remove('btn-loading');
                            submitButton.disabled = false;
                        }
                    }
                });
            }
        });
    </script>
</body>
</html>