<?php
/**
 * Email Verification Page
 * 
 * Handle email verification with tokens and resend functionality
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Email Verification - E-Commerce Authentication');

// Include required files
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/validation.php';
require_once __DIR__ . '/includes/session.php';

// Initialize session
SessionManager::init();

$errors = [];
$success = false;
$message = '';
$showResendForm = false;

// Handle token verification (GET request)
if (isset($_GET['token'])) {
    $token = trim($_GET['token']);
    
    if (!empty($token)) {
        $verificationResult = AuthFunctions::verifyEmail($token);
        
        if ($verificationResult['success']) {
            $success = true;
            $message = $verificationResult['message'];
        } else {
            $errors['general'] = $verificationResult['errors'];
            $showResendForm = true;
        }
    } else {
        $errors['general'] = ['Invalid verification token'];
        $showResendForm = true;
    }
}

// Handle resend verification email (POST request)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Validate CSRF token
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'verify')) {
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
            // Check if user exists and is not already verified
            $userQuery = "SELECT id, username, email, is_verified FROM users WHERE email = ? AND is_active = 1";
            $userStmt = DatabaseConfig::executeQuery($userQuery, [$email]);
            $user = $userStmt->fetch();
            
            if (!$user) {
                // Don't reveal if email exists for security
                $message = 'If an account with that email exists and is not verified, a verification email has been sent.';
            } elseif ($user['is_verified']) {
                $message = 'Your email address is already verified. You can now <a href="login.php">sign in</a>.';
            } else {
                // Generate new verification token
                $verificationToken = SecurityConfig::generateSecureToken();
                $verificationExpiry = date('Y-m-d H:i:s', time() + SecurityConfig::VERIFICATION_TOKEN_EXPIRY);
                
                // Insert new verification token (deactivate old ones)
                DatabaseConfig::beginTransaction();
                
                try {
                    // Deactivate old tokens
                    $deactivateQuery = "UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL";
                    DatabaseConfig::executeQuery($deactivateQuery, [$user['id']]);
                    
                    // Insert new token
                    $tokenQuery = "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)";
                    DatabaseConfig::executeQuery($tokenQuery, [$user['id'], $verificationToken, $verificationExpiry]);
                    
                    DatabaseConfig::commit();
                    
                    // Send verification email
                    $emailResult = EmailConfig::sendVerificationEmail($user['email'], $user['username'], $verificationToken);
                    
                    if ($emailResult['success']) {
                        $message = 'A new verification email has been sent to your email address. Please check your inbox and spam folder.';
                    } else {
                        $message = 'Account found, but verification email could not be sent. Please contact support.';
                    }
                    
                } catch (Exception $e) {
                    DatabaseConfig::rollback();
                    throw $e;
                }
            }
        }
        
        // If AJAX request, return JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => empty($errors),
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

// Show resend form if no token provided or verification failed
if (!isset($_GET['token']) || (!$success && !$message)) {
    $showResendForm = true;
}

// Pre-fill email from URL parameter
$prefilledEmail = $_GET['email'] ?? '';

// Generate CSRF token for the form
$csrfToken = SecurityConfig::generateCSRFToken('verify');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Verify your email address to activate your e-commerce account and start shopping securely.">
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
            <span class="icon">📧</span>
            <h1><?php echo $success ? 'Email Verified!' : 'Email Verification'; ?></h1>
            <p><?php echo $success ? 'Your account is now active' : 'Activate your account'; ?></p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <?php if ($success): ?>
                <!-- Success State -->
                <div class="alert alert-success">
                    <strong>✅ Verification Successful!</strong><br>
                    <?php echo htmlspecialchars($message); ?>
                </div>
                
                <div class="text-center" style="margin: 30px 0;">
                    <div style="font-size: 4rem; margin-bottom: 20px;">🎉</div>
                    <h3>Welcome to our platform!</h3>
                    <p>Your email has been successfully verified. You can now access all features of your account.</p>
                </div>
                
                <div class="auth-links">
                    <a href="login.php" class="btn btn-primary btn-full">Sign In Now</a>
                    <p style="margin-top: 15px;"><a href="dashboard.php">Go to Dashboard</a></p>
                </div>
                
            <?php elseif (!empty($message)): ?>
                <!-- Message State -->
                <div class="alert alert-info">
                    <?php echo $message; ?>
                </div>
                
                <div class="auth-links">
                    <p><a href="login.php">Back to Login</a></p>
                    <p><a href="register.php">Create New Account</a></p>
                </div>
                
            <?php else: ?>
                <!-- Display general errors -->
                <?php if (!empty($errors['general'])): ?>
                    <div class="alert alert-error">
                        <?php foreach ($errors['general'] as $error): ?>
                            <div><?php echo htmlspecialchars($error); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($showResendForm): ?>
                    <!-- Resend Verification Form -->
                    <div class="text-center" style="margin-bottom: 30px;">
                        <div style="font-size: 3rem; margin-bottom: 15px;">📬</div>
                        <h3>Resend Verification Email</h3>
                        <p>Enter your email address and we'll send you a new verification link.</p>
                    </div>
                    
                    <form method="POST" action="verify.php" class="auth-form" novalidate>
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        
                        <!-- Email -->
                        <div class="form-group <?php echo !empty($errors['email']) ? 'has-error' : ''; ?>">
                            <label for="email">Email Address *</label>
                            <div class="input-icon">
                                <input 
                                    type="email" 
                                    id="email" 
                                    name="email" 
                                    value="<?php echo htmlspecialchars($prefilledEmail); ?>"
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
                        </div>
                        
                        <!-- Submit Button -->
                        <button type="submit" class="btn btn-primary btn-full">
                            Send Verification Email
                        </button>
                    </form>
                    
                    <!-- Information -->
                    <div class="alert alert-info" style="margin-top: 30px;">
                        <strong>💡 Tips:</strong>
                        <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                            <li>Check your spam/junk folder if you don't see the email</li>
                            <li>Verification links expire after 24 hours</li>
                            <li>You can request a new verification email anytime</li>
                            <li>Make sure your email address is correct</li>
                        </ul>
                    </div>
                    
                <?php else: ?>
                    <!-- No token provided state -->
                    <div class="text-center" style="margin-bottom: 30px;">
                        <div style="font-size: 3rem; margin-bottom: 15px;">❓</div>
                        <h3>Email Verification Required</h3>
                        <p>Please click the verification link sent to your email address, or request a new one below.</p>
                    </div>
                    
                    <div class="auth-links">
                        <a href="verify.php?resend=1" class="btn btn-primary btn-full">Request Verification Email</a>
                        <p style="margin-top: 15px;"><a href="login.php">Back to Login</a></p>
                        <p><a href="register.php">Create New Account</a></p>
                    </div>
                <?php endif; ?>
                
                <!-- Additional Links -->
                <div class="auth-links" style="border-top: 1px solid #e1e5e9; margin-top: 30px; padding-top: 20px;">
                    <p><a href="login.php">← Back to Login</a></p>
                    <p><a href="forgot-password.php">Forgot Password?</a></p>
                    <p><a href="/contact">Contact Support</a></p>
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
            // Auto-focus on email input if form is visible
            const emailInput = document.querySelector('input[name="email"]');
            if (emailInput && emailInput.offsetParent !== null) {
                emailInput.focus();
            }
            
            // Handle form submission with enhanced feedback
            const form = document.querySelector('.auth-form');
            if (form) {
                form.addEventListener('submit', function(e) {
                    const submitButton = form.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.textContent = 'Sending Email...';
                    }
                });
            }
            
            // Auto-redirect after successful verification
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
            
            // Check URL parameters
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('resend') === '1') {
                // Show resend form
                const form = document.querySelector('.auth-form');
                if (form) {
                    form.scrollIntoView({ behavior: 'smooth' });
                }
            }
            
            // Enhanced email validation feedback
            if (emailInput) {
                emailInput.addEventListener('input', function() {
                    const formGroup = this.closest('.form-group');
                    
                    // Clear previous validation
                    formGroup.classList.remove('has-error', 'has-success');
                    const errorMessages = formGroup.querySelectorAll('.error-message');
                    errorMessages.forEach(msg => msg.remove());
                    
                    // Validate email format
                    if (this.value && window.AuthUtils.validateEmail(this.value)) {
                        formGroup.classList.add('has-success');
                    } else if (this.value) {
                        formGroup.classList.add('has-error');
                        const errorMsg = document.createElement('span');
                        errorMsg.className = 'error-message';
                        errorMsg.textContent = 'Please enter a valid email address';
                        formGroup.appendChild(errorMsg);
                    }
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
            
            // Add visual feedback for successful verification
            <?php if ($success): ?>
            // Add celebration animation
            const icon = document.querySelector('.auth-header .icon');
            if (icon) {
                icon.style.animation = 'bounce 2s ease-in-out infinite';
            }
            
            // Add CSS for bounce animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes bounce {
                    0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
                    40% { transform: translateY(-10px); }
                    60% { transform: translateY(-5px); }
                }
            `;
            document.head.appendChild(style);
            <?php endif; ?>
        });
    </script>
</body>
</html>