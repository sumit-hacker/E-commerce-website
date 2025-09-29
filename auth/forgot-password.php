<?php
/**
 * Forgot Password Page
 * 
 * Handle password reset requests with rate limiting and security
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Forgot Password - E-Commerce Authentication');

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

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Validate CSRF token
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'forgot_password')) {
            throw new Exception('Invalid security token. Please try again.');
        }
        
        $email = trim($_POST['email'] ?? '');
        
        if (empty($email)) {
            $errors['email'] = ['Email address is required'];
        } else {
            // Validate email format
            $emailValidation = ValidationHelper::validate($email, 'email');
            if (!$emailValidation['valid']) {
                $errors['email'] = [$emailValidation['errors'][0] ?? 'Invalid email format'];
            }
        }
        
        if (empty($errors)) {
            // Request password reset
            $resetResult = AuthFunctions::requestPasswordReset($email);
            
            if ($resetResult['success']) {
                $success = true;
                $message = $resetResult['message'];
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
$csrfToken = SecurityConfig::generateCSRFToken('forgot_password');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Reset your password securely with our e-commerce authentication system.">
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
            <span class="icon">🔐</span>
            <h1>Forgot Password?</h1>
            <p>Reset your password securely</p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <?php if ($success): ?>
                <!-- Success State -->
                <div class="alert alert-success">
                    <strong>✅ Reset Email Sent!</strong><br>
                    <?php echo htmlspecialchars($message); ?>
                </div>
                
                <div class="text-center" style="margin: 30px 0;">
                    <div style="font-size: 4rem; margin-bottom: 20px;">📧</div>
                    <h3>Check Your Email</h3>
                    <p>We've sent password reset instructions to your email address. Please check your inbox and spam folder.</p>
                </div>
                
                <div class="alert alert-info">
                    <strong>💡 Next Steps:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Check your email for the reset link</li>
                        <li>Click the link to reset your password</li>
                        <li>The link expires in 15 minutes for security</li>
                        <li>You can request a new link if needed</li>
                    </ul>
                </div>
                
                <div class="auth-links">
                    <p><a href="login.php">← Back to Login</a></p>
                    <p><a href="forgot-password.php">Request Another Reset Email</a></p>
                </div>
                
            <?php else: ?>
                <!-- Reset Request Form -->
                <div class="text-center" style="margin-bottom: 30px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">🔒</div>
                    <h3>Reset Your Password</h3>
                    <p>Enter your email address and we'll send you a link to reset your password.</p>
                </div>
                
                <form method="POST" action="forgot-password.php" class="auth-form" novalidate>
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    
                    <!-- Display general errors -->
                    <?php if (!empty($errors['general'])): ?>
                        <div class="alert alert-error">
                            <?php foreach ($errors['general'] as $error): ?>
                                <div><?php echo htmlspecialchars($error); ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <!-- Email -->
                    <div class="form-group <?php echo !empty($errors['email']) ? 'has-error' : ''; ?>">
                        <label for="email">Email Address *</label>
                        <div class="input-icon">
                            <input 
                                type="email" 
                                id="email" 
                                name="email" 
                                value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
                                required 
                                data-validate="email"
                                placeholder="Enter your email address"
                                autocomplete="email"
                                maxlength="255"
                                autofocus
                            >
                            <i>📧</i>
                        </div>
                        <?php if (!empty($errors['email'])): ?>
                            <?php foreach ($errors['email'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        <small style="color: #666; font-size: 0.85rem; margin-top: 5px; display: block;">
                            We'll send reset instructions to this email address
                        </small>
                    </div>
                    
                    <!-- Submit Button -->
                    <button type="submit" class="btn btn-primary btn-full">
                        Send Reset Instructions
                    </button>
                </form>
                
                <!-- Security Information -->
                <div class="alert alert-info" style="margin-top: 30px;">
                    <strong>🔒 Security Features:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Reset links expire after 15 minutes</li>
                        <li>Only the most recent reset link is valid</li>
                        <li>We don't reveal if an email exists in our system</li>
                        <li>All reset attempts are logged and monitored</li>
                    </ul>
                </div>
                
                <!-- Links -->
                <div class="auth-links">
                    <p><a href="login.php">← Back to Login</a></p>
                    <p>Remember your password? <a href="login.php">Sign In</a></p>
                    <p>Don't have an account? <a href="register.php">Create Account</a></p>
                </div>
                
                <!-- Additional Help -->
                <div class="alert alert-warning" style="margin-top: 30px;">
                    <strong>⚠️ Still Having Trouble?</strong><br>
                    If you don't receive the reset email within a few minutes:
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Check your spam/junk folder</li>
                        <li>Make sure you entered the correct email address</li>
                        <li>Try requesting another reset email</li>
                        <li>Contact our support team if the problem persists</li>
                    </ul>
                    <p style="margin-top: 15px;"><a href="/contact">Contact Support</a></p>
                </div>
            <?php endif; ?>
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
            // Auto-focus on email input
            const emailInput = document.querySelector('input[name="email"]');
            if (emailInput && !emailInput.value) {
                emailInput.focus();
            }
            
            // Handle form submission with enhanced feedback
            const form = document.querySelector('.auth-form');
            if (form) {
                form.addEventListener('submit', function(e) {
                    const submitButton = form.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.textContent = 'Sending Instructions...';
                    }
                });
            }
            
            // Enhanced email validation with domain suggestions
            if (emailInput) {
                const commonDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'];
                
                emailInput.addEventListener('input', function() {
                    const formGroup = this.closest('.form-group');
                    
                    // Clear previous validation
                    formGroup.classList.remove('has-error', 'has-success');
                    const errorMessages = formGroup.querySelectorAll('.error-message, .suggestion-message');
                    errorMessages.forEach(msg => msg.remove());
                    
                    if (this.value) {
                        // Validate email format
                        if (window.AuthUtils.validateEmail(this.value)) {
                            formGroup.classList.add('has-success');
                        } else {
                            formGroup.classList.add('has-error');
                            const errorMsg = document.createElement('span');
                            errorMsg.className = 'error-message';
                            errorMsg.textContent = 'Please enter a valid email address';
                            formGroup.appendChild(errorMsg);
                            
                            // Suggest common domains for typos
                            const emailParts = this.value.split('@');
                            if (emailParts.length === 2 && emailParts[1]) {
                                const domain = emailParts[1].toLowerCase();
                                const suggestion = findClosestDomain(domain, commonDomains);
                                
                                if (suggestion && suggestion !== domain) {
                                    const suggestionMsg = document.createElement('span');
                                    suggestionMsg.className = 'suggestion-message';
                                    suggestionMsg.style.cssText = 'color: #007bff; font-size: 0.85rem; margin-top: 5px; display: block; cursor: pointer;';
                                    suggestionMsg.innerHTML = `Did you mean <strong>${emailParts[0]}@${suggestion}</strong>? <small>(click to use)</small>`;
                                    suggestionMsg.addEventListener('click', () => {
                                        emailInput.value = `${emailParts[0]}@${suggestion}`;
                                        emailInput.dispatchEvent(new Event('input'));
                                    });
                                    formGroup.appendChild(suggestionMsg);
                                }
                            }
                        }
                    }
                });
            }
            
            // Rate limiting feedback
            let attemptCount = parseInt(localStorage.getItem('passwordResetAttempts') || '0');
            let lastAttempt = parseInt(localStorage.getItem('passwordResetLastAttempt') || '0');
            const now = Date.now();
            
            // Reset count if more than 1 hour has passed
            if (now - lastAttempt > 3600000) {
                attemptCount = 0;
                localStorage.removeItem('passwordResetAttempts');
                localStorage.removeItem('passwordResetLastAttempt');
            }
            
            if (attemptCount >= 3) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'alert alert-warning';
                warningDiv.innerHTML = `
                    <strong>⚠️ Rate Limit Notice:</strong><br>
                    You've requested ${attemptCount} password resets in the past hour. 
                    Please wait before requesting another reset to prevent abuse.
                `;
                
                const form = document.querySelector('.auth-form');
                if (form) {
                    form.parentNode.insertBefore(warningDiv, form);
                }
            }
            
            // Track attempts
            if (form) {
                form.addEventListener('submit', function() {
                    attemptCount++;
                    localStorage.setItem('passwordResetAttempts', attemptCount.toString());
                    localStorage.setItem('passwordResetLastAttempt', Date.now().toString());
                });
            }
            
            // Add keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // ESC key to go back to login
                if (e.key === 'Escape') {
                    window.location.href = 'login.php';
                }
                
                // Enter key on email input to submit form
                if (e.key === 'Enter' && e.target === emailInput) {
                    e.preventDefault();
                    if (form && emailInput.value.trim()) {
                        form.submit();
                    }
                }
            });
            
            // Auto-redirect timer for success state
            <?php if ($success): ?>
            let countdown = 30;
            const updateCountdown = () => {
                const backLink = document.querySelector('a[href="login.php"]');
                if (backLink && countdown > 0) {
                    const originalText = backLink.textContent.replace(/ \(\d+\)/, '');
                    backLink.textContent = `${originalText} (${countdown})`;
                    countdown--;
                    setTimeout(updateCountdown, 1000);
                } else if (!document.querySelector('a[href="login.php"]:hover')) {
                    // Only redirect if user is not hovering over the link
                    window.location.href = 'login.php';
                }
            };
            setTimeout(updateCountdown, 5000);
            <?php endif; ?>
        });
        
        // Helper function to find closest domain for typo suggestions
        function findClosestDomain(domain, commonDomains) {
            let closest = null;
            let minDistance = Infinity;
            
            commonDomains.forEach(commonDomain => {
                const distance = levenshteinDistance(domain, commonDomain);
                if (distance < minDistance && distance <= 2) {
                    minDistance = distance;
                    closest = commonDomain;
                }
            });
            
            return closest;
        }
        
        // Levenshtein distance algorithm for string similarity
        function levenshteinDistance(str1, str2) {
            const matrix = [];
            
            for (let i = 0; i <= str2.length; i++) {
                matrix[i] = [i];
            }
            
            for (let j = 0; j <= str1.length; j++) {
                matrix[0][j] = j;
            }
            
            for (let i = 1; i <= str2.length; i++) {
                for (let j = 1; j <= str1.length; j++) {
                    if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                        matrix[i][j] = matrix[i - 1][j - 1];
                    } else {
                        matrix[i][j] = Math.min(
                            matrix[i - 1][j - 1] + 1,
                            matrix[i][j - 1] + 1,
                            matrix[i - 1][j] + 1
                        );
                    }
                }
            }
            
            return matrix[str2.length][str1.length];
        }
    </script>
</body>
</html>