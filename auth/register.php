<?php
/**
 * User Registration Page
 * 
 * Secure user registration with validation, rate limiting,
 * and email verification for the authentication system.
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Register - E-Commerce Authentication');

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

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Validate CSRF token
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'register')) {
            throw new Exception('Invalid security token. Please try again.');
        }
        
        // Check rate limiting
        $clientIP = SecurityConfig::getClientIP();
        $rateLimit = SecurityConfig::checkRateLimit('registration', $clientIP);
        if (!$rateLimit['allowed']) {
            throw new Exception($rateLimit['message']);
        }
        
        // Get and validate form data
        $formData = [
            'username' => trim($_POST['username'] ?? ''),
            'email' => trim($_POST['email'] ?? ''),
            'password' => $_POST['password'] ?? '',
            'confirm_password' => $_POST['confirm_password'] ?? '',
            'first_name' => trim($_POST['first_name'] ?? ''),
            'last_name' => trim($_POST['last_name'] ?? ''),
            'phone' => trim($_POST['phone'] ?? ''),
            'accept_terms' => isset($_POST['accept_terms'])
        ];
        
        // Validate using ValidationHelper
        $validationRules = ValidationHelper::getCommonRules()['registration'];
        $validation = ValidationHelper::validateMultiple($formData, $validationRules);
        
        if (!$validation['valid']) {
            $errors = $validation['errors'];
        }
        
        // Additional custom validations
        if (empty($errors)) {
            // Check password confirmation
            if ($formData['password'] !== $formData['confirm_password']) {
                $errors['confirm_password'] = ['Passwords do not match'];
            }
            
            // Check terms acceptance
            if (!$formData['accept_terms']) {
                $errors['accept_terms'] = ['You must accept the terms and conditions'];
            }
        }
        
        // If validation passed, attempt registration
        if (empty($errors)) {
            $registrationResult = AuthFunctions::registerUser($formData);
            
            if ($registrationResult['success']) {
                $success = true;
                
                // Clear form data on success
                $formData = [];
                
                // If AJAX request, return JSON
                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
                    header('Content-Type: application/json');
                    echo json_encode([
                        'success' => true,
                        'message' => $registrationResult['message'],
                        'action' => 'registration_success'
                    ]);
                    exit;
                }
            } else {
                $errors['general'] = $registrationResult['errors'];
                SecurityConfig::recordAttempt('registration', $clientIP);
            }
        } else {
            SecurityConfig::recordAttempt('registration', $clientIP);
        }
        
        // If AJAX request, return JSON response
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
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
$csrfToken = SecurityConfig::generateCSRFToken('register');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Create your account for secure access to our e-commerce platform with advanced authentication features.">
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
            <h1>Create Account</h1>
            <p>Join our secure e-commerce platform</p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <?php if ($success): ?>
                <div class="alert alert-success">
                    <strong>Registration Successful!</strong><br>
                    Your account has been created successfully. Please check your email to verify your account before logging in.
                </div>
                
                <div class="auth-links">
                    <p><a href="login.php">Proceed to Login</a></p>
                    <p><a href="verify.php">Resend Verification Email</a></p>
                </div>
                
            <?php else: ?>
                <!-- Registration Form -->
                <form method="POST" action="register.php" class="auth-form" novalidate>
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    
                    <!-- Display general errors -->
                    <?php if (!empty($errors['general'])): ?>
                        <div class="alert alert-error">
                            <?php foreach ($errors['general'] as $error): ?>
                                <div><?php echo htmlspecialchars($error); ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <!-- Username -->
                    <div class="form-group <?php echo !empty($errors['username']) ? 'has-error' : ''; ?>">
                        <label for="username">Username *</label>
                        <div class="input-icon">
                            <input 
                                type="text" 
                                id="username" 
                                name="username" 
                                value="<?php echo htmlspecialchars($formData['username'] ?? ''); ?>"
                                required 
                                data-validate="username"
                                placeholder="Enter your username"
                                autocomplete="username"
                                maxlength="30"
                            >
                            <i>👤</i>
                        </div>
                        <?php if (!empty($errors['username'])): ?>
                            <?php foreach ($errors['username'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Email -->
                    <div class="form-group <?php echo !empty($errors['email']) ? 'has-error' : ''; ?>">
                        <label for="email">Email Address *</label>
                        <div class="input-icon">
                            <input 
                                type="email" 
                                id="email" 
                                name="email" 
                                value="<?php echo htmlspecialchars($formData['email'] ?? ''); ?>"
                                required 
                                data-validate="email"
                                placeholder="Enter your email address"
                                autocomplete="email"
                                maxlength="255"
                            >
                            <i>📧</i>
                        </div>
                        <?php if (!empty($errors['email'])): ?>
                            <?php foreach ($errors['email'] as $error): ?>
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
                                data-validate="password"
                                placeholder="Create a strong password"
                                autocomplete="new-password"
                                minlength="8"
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
                    
                    <!-- Confirm Password -->
                    <div class="form-group <?php echo !empty($errors['confirm_password']) ? 'has-error' : ''; ?>">
                        <label for="confirm_password">Confirm Password *</label>
                        <div class="input-icon">
                            <input 
                                type="password" 
                                id="confirm_password" 
                                name="confirm_password" 
                                required 
                                placeholder="Confirm your password"
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
                    
                    <!-- First Name -->
                    <div class="form-group <?php echo !empty($errors['first_name']) ? 'has-error' : ''; ?>">
                        <label for="first_name">First Name</label>
                        <div class="input-icon">
                            <input 
                                type="text" 
                                id="first_name" 
                                name="first_name" 
                                value="<?php echo htmlspecialchars($formData['first_name'] ?? ''); ?>"
                                data-validate="name"
                                placeholder="Enter your first name"
                                autocomplete="given-name"
                                maxlength="100"
                            >
                            <i>👤</i>
                        </div>
                        <?php if (!empty($errors['first_name'])): ?>
                            <?php foreach ($errors['first_name'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Last Name -->
                    <div class="form-group <?php echo !empty($errors['last_name']) ? 'has-error' : ''; ?>">
                        <label for="last_name">Last Name</label>
                        <div class="input-icon">
                            <input 
                                type="text" 
                                id="last_name" 
                                name="last_name" 
                                value="<?php echo htmlspecialchars($formData['last_name'] ?? ''); ?>"
                                data-validate="name"
                                placeholder="Enter your last name"
                                autocomplete="family-name"
                                maxlength="100"
                            >
                            <i>👤</i>
                        </div>
                        <?php if (!empty($errors['last_name'])): ?>
                            <?php foreach ($errors['last_name'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Phone -->
                    <div class="form-group <?php echo !empty($errors['phone']) ? 'has-error' : ''; ?>">
                        <label for="phone">Phone Number</label>
                        <div class="input-icon">
                            <input 
                                type="tel" 
                                id="phone" 
                                name="phone" 
                                value="<?php echo htmlspecialchars($formData['phone'] ?? ''); ?>"
                                data-validate="phone"
                                placeholder="Enter your phone number"
                                autocomplete="tel"
                                maxlength="20"
                            >
                            <i>📱</i>
                        </div>
                        <?php if (!empty($errors['phone'])): ?>
                            <?php foreach ($errors['phone'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Terms and Conditions -->
                    <div class="form-group <?php echo !empty($errors['accept_terms']) ? 'has-error' : ''; ?>">
                        <div class="checkbox-group">
                            <input 
                                type="checkbox" 
                                id="accept_terms" 
                                name="accept_terms" 
                                value="1"
                                <?php echo (!empty($formData['accept_terms'])) ? 'checked' : ''; ?>
                                required
                            >
                            <label for="accept_terms">
                                I agree to the <a href="/terms" target="_blank">Terms of Service</a> 
                                and <a href="/privacy" target="_blank">Privacy Policy</a> *
                            </label>
                        </div>
                        <?php if (!empty($errors['accept_terms'])): ?>
                            <?php foreach ($errors['accept_terms'] as $error): ?>
                                <span class="error-message"><?php echo htmlspecialchars($error); ?></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                    <!-- Submit Button -->
                    <button type="submit" class="btn btn-primary btn-full">
                        Create Account
                    </button>
                </form>
                
                <!-- Links -->
                <div class="auth-links">
                    <p>Already have an account? <a href="login.php">Sign In</a></p>
                    <p><a href="forgot-password.php">Forgot Password?</a></p>
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
            // Focus on first input
            const firstInput = document.querySelector('input:not([type="hidden"])');
            if (firstInput) {
                firstInput.focus();
            }
            
            // Add form-specific enhancements
            const form = document.querySelector('.auth-form');
            if (form) {
                // Real-time username availability check (debounced)
                const usernameInput = form.querySelector('input[name="username"]');
                if (usernameInput) {
                    let checkTimeout;
                    usernameInput.addEventListener('input', function() {
                        clearTimeout(checkTimeout);
                        checkTimeout = setTimeout(() => {
                            checkUsernameAvailability(this.value);
                        }, 1000);
                    });
                }
                
                // Real-time email availability check (debounced)
                const emailInput = form.querySelector('input[name="email"]');
                if (emailInput) {
                    let emailCheckTimeout;
                    emailInput.addEventListener('input', function() {
                        clearTimeout(emailCheckTimeout);
                        emailCheckTimeout = setTimeout(() => {
                            checkEmailAvailability(this.value);
                        }, 1000);
                    });
                }
            }
        });
        
        async function checkUsernameAvailability(username) {
            if (username.length < 3) return;
            
            try {
                const response = await fetch('check-availability.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({ type: 'username', value: username })
                });
                
                const result = await response.json();
                const usernameGroup = document.querySelector('input[name="username"]').closest('.form-group');
                
                if (result.available === false) {
                    usernameGroup.classList.add('has-error');
                    usernameGroup.classList.remove('has-success');
                    
                    // Remove existing messages
                    const existingMsg = usernameGroup.querySelector('.availability-message');
                    if (existingMsg) existingMsg.remove();
                    
                    const errorMsg = document.createElement('span');
                    errorMsg.className = 'error-message availability-message';
                    errorMsg.textContent = 'Username is already taken';
                    usernameGroup.appendChild(errorMsg);
                } else if (result.available === true) {
                    usernameGroup.classList.add('has-success');
                    usernameGroup.classList.remove('has-error');
                    
                    // Remove any error messages
                    const errorMessages = usernameGroup.querySelectorAll('.availability-message');
                    errorMessages.forEach(msg => msg.remove());
                }
            } catch (error) {
                console.error('Username availability check failed:', error);
            }
        }
        
        async function checkEmailAvailability(email) {
            if (!email.includes('@')) return;
            
            try {
                const response = await fetch('check-availability.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({ type: 'email', value: email })
                });
                
                const result = await response.json();
                const emailGroup = document.querySelector('input[name="email"]').closest('.form-group');
                
                if (result.available === false) {
                    emailGroup.classList.add('has-error');
                    emailGroup.classList.remove('has-success');
                    
                    // Remove existing messages
                    const existingMsg = emailGroup.querySelector('.availability-message');
                    if (existingMsg) existingMsg.remove();
                    
                    const errorMsg = document.createElement('span');
                    errorMsg.className = 'error-message availability-message';
                    errorMsg.textContent = 'Email is already registered';
                    emailGroup.appendChild(errorMsg);
                } else if (result.available === true) {
                    emailGroup.classList.add('has-success');
                    emailGroup.classList.remove('has-error');
                    
                    // Remove any error messages
                    const errorMessages = emailGroup.querySelectorAll('.availability-message');
                    errorMessages.forEach(msg => msg.remove());
                }
            } catch (error) {
                console.error('Email availability check failed:', error);
            }
        }
    </script>
</body>
</html>