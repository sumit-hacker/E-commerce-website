<?php
/**
 * User Logout Page
 * 
 * Secure logout with session cleanup and user feedback
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Logout - E-Commerce Authentication');

// Include required files
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/session.php';

// Initialize session
SessionManager::init();

$message = '';
$success = false;
$username = '';

// Get current user info before logout
$loginCheck = SessionManager::isValidUserSession();
if ($loginCheck['valid']) {
    $username = $loginCheck['username'] ?? 'User';
}

// Handle logout request
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['confirm'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Validate CSRF token for POST requests
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'logout')) {
            $message = 'Invalid security token. Please try again.';
        } else {
            // Perform logout
            $logoutResult = AuthFunctions::logoutUser();
            $success = $logoutResult['success'];
            $message = $logoutResult['message'];
        }
    } else {
        // Direct logout via GET parameter (less secure but convenient)
        $logoutResult = AuthFunctions::logoutUser();
        $success = $logoutResult['success'];
        $message = $logoutResult['message'];
    }
    
    // If AJAX request, return JSON response
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => $success,
            'message' => $message,
            'redirect' => 'login.php'
        ]);
        exit;
    }
} else {
    // Show logout confirmation if user is logged in
    if ($loginCheck['valid']) {
        $message = 'Are you sure you want to log out?';
    } else {
        $message = 'You are already logged out.';
        $success = true;
    }
}

// Generate CSRF token for the form
$csrfToken = SecurityConfig::generateCSRFToken('logout');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Securely log out from your e-commerce account.">
    <meta name="robots" content="noindex, nofollow">
    
    <!-- Stylesheets -->
    <link rel="stylesheet" href="css/auth.css">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    
    <!-- Auto-redirect if logged out -->
    <?php if ($success): ?>
    <meta http-equiv="refresh" content="5;url=login.php">
    <?php endif; ?>
</head>
<body>
    <div class="auth-container fade-in">
        <!-- Header -->
        <div class="auth-header">
            <span class="icon"><?php echo $success ? '👋' : '🚪'; ?></span>
            <h1><?php echo $success ? 'Logged Out' : 'Logout'; ?></h1>
            <p><?php echo $success ? 'See you next time!' : 'Sign out securely'; ?></p>
        </div>
        
        <!-- Content -->
        <div class="auth-content">
            <?php if ($success): ?>
                <!-- Success State -->
                <div class="alert alert-success">
                    <strong>✅ Logout Successful!</strong><br>
                    <?php echo htmlspecialchars($message); ?>
                </div>
                
                <div class="text-center" style="margin: 30px 0;">
                    <div style="font-size: 4rem; margin-bottom: 20px;">👋</div>
                    <?php if (!empty($username)): ?>
                        <h3>Goodbye, <?php echo htmlspecialchars($username); ?>!</h3>
                    <?php else: ?>
                        <h3>Goodbye!</h3>
                    <?php endif; ?>
                    <p>You have been securely logged out of your account.</p>
                </div>
                
                <div class="alert alert-info">
                    <strong>🔒 Security Notice:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Your session has been terminated</li>
                        <li>All temporary data has been cleared</li>
                        <li>Your account remains secure</li>
                        <li>You'll need to log in again to access your account</li>
                    </ul>
                </div>
                
                <div class="auth-links">
                    <a href="login.php" class="btn btn-primary btn-full">Sign In Again</a>
                    <p style="margin-top: 15px;"><a href="register.php">Create New Account</a></p>
                    <p><a href="/">Return to Homepage</a></p>
                </div>
                
            <?php elseif ($loginCheck['valid']): ?>
                <!-- Logout Confirmation -->
                <div class="text-center" style="margin-bottom: 30px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">🚪</div>
                    <h3>Confirm Logout</h3>
                    <p><?php echo htmlspecialchars($message); ?></p>
                    <?php if (!empty($username)): ?>
                        <p><strong>Current user:</strong> <?php echo htmlspecialchars($username); ?></p>
                    <?php endif; ?>
                </div>
                
                <form method="POST" action="logout.php" class="auth-form">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    
                    <div style="display: flex; gap: 15px; margin-top: 30px;">
                        <button type="submit" class="btn btn-danger" style="flex: 1;">
                            Yes, Log Out
                        </button>
                        <a href="dashboard.php" class="btn btn-secondary" style="flex: 1; text-decoration: none; display: flex; align-items: center; justify-content: center;">
                            Cancel
                        </a>
                    </div>
                </form>
                
                <div class="alert alert-warning" style="margin-top: 30px;">
                    <strong>⚠️ Before You Go:</strong>
                    <ul style="margin: 10px 0 0 20px; font-size: 0.9rem;">
                        <li>Make sure you've saved any unsaved work</li>
                        <li>You'll need to log in again to access your account</li>
                        <li>Consider using "Remember Me" for future logins</li>
                        <li>Close your browser if using a shared computer</li>
                    </ul>
                </div>
                
                <!-- Quick Logout Link -->
                <div class="auth-links" style="border-top: 1px solid #e1e5e9; margin-top: 30px; padding-top: 20px;">
                    <p><a href="logout.php?confirm=1" style="color: #dc3545;">Quick Logout (Skip Confirmation)</a></p>
                    <p><a href="dashboard.php">← Back to Dashboard</a></p>
                </div>
                
            <?php else: ?>
                <!-- Already Logged Out -->
                <div class="text-center" style="margin-bottom: 30px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">ℹ️</div>
                    <h3>Already Logged Out</h3>
                    <p><?php echo htmlspecialchars($message); ?></p>
                </div>
                
                <div class="auth-links">
                    <a href="login.php" class="btn btn-primary btn-full">Sign In</a>
                    <p style="margin-top: 15px;"><a href="register.php">Create Account</a></p>
                    <p><a href="/">Return to Homepage</a></p>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="js/auth.js"></script>
    
    <!-- Additional page-specific JavaScript -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-redirect countdown for success state
            <?php if ($success): ?>
            let countdown = 5;
            const updateCountdown = () => {
                const loginButton = document.querySelector('a[href="login.php"]');
                if (loginButton && countdown > 0) {
                    const originalText = loginButton.textContent.replace(/ \(\d+\)/, '');
                    loginButton.textContent = `${originalText} (${countdown})`;
                    countdown--;
                    setTimeout(updateCountdown, 1000);
                } else {
                    window.location.href = 'login.php';
                }
            };
            setTimeout(updateCountdown, 1000);
            
            // Stop redirect if user interacts with the page
            document.addEventListener('click', function() {
                countdown = -1;
                const loginButton = document.querySelector('a[href="login.php"]');
                if (loginButton) {
                    loginButton.textContent = loginButton.textContent.replace(/ \(\d+\)/, '');
                }
            });
            <?php endif; ?>
            
            // Enhanced logout confirmation
            const logoutForm = document.querySelector('.auth-form');
            if (logoutForm) {
                logoutForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    // Show loading state
                    const submitButton = this.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.textContent = 'Logging Out...';
                        submitButton.disabled = true;
                    }
                    
                    // Add a slight delay for better UX
                    setTimeout(() => {
                        this.submit();
                    }, 500);
                });
            }
            
            // Quick logout functionality
            const quickLogoutLink = document.querySelector('a[href="logout.php?confirm=1"]');
            if (quickLogoutLink) {
                quickLogoutLink.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Show inline confirmation
                    const confirmation = confirm('Are you sure you want to log out immediately?');
                    if (confirmation) {
                        window.location.href = this.href;
                    }
                });
            }
            
            // Add keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // ESC key to cancel logout
                if (e.key === 'Escape' && !document.querySelector('.alert-success')) {
                    window.location.href = 'dashboard.php';
                }
                
                // Enter key to confirm logout
                if (e.key === 'Enter' && logoutForm) {
                    const submitButton = logoutForm.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.click();
                    }
                }
            });
            
            // Clear any sensitive data from localStorage/sessionStorage
            <?php if ($success): ?>
            try {
                // Clear any auth-related local storage
                const keysToRemove = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key && (key.includes('auth') || key.includes('user') || key.includes('session'))) {
                        keysToRemove.push(key);
                    }
                }
                keysToRemove.forEach(key => localStorage.removeItem(key));
                
                // Clear session storage
                sessionStorage.clear();
                
                // Clear any cached form data
                const forms = document.querySelectorAll('form');
                forms.forEach(form => {
                    if (form.reset) form.reset();
                });
                
            } catch (error) {
                console.log('Storage cleanup completed with minor issues');
            }
            <?php endif; ?>
            
            // Security: Prevent back button after logout
            <?php if ($success): ?>
            history.pushState(null, null, window.location.href);
            window.addEventListener('popstate', function() {
                history.pushState(null, null, window.location.href);
                window.location.href = 'login.php';
            });
            <?php endif; ?>
            
            // Show logout confirmation modal for better UX
            if (logoutForm) {
                const showModal = localStorage.getItem('showLogoutModal');
                if (showModal !== 'false') {
                    // You can implement a modal here if desired
                    // For now, we'll just focus on the first button
                    const submitButton = logoutForm.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.focus();
                    }
                }
            }
        });
        
        // Global logout function for other pages to use
        window.performLogout = function(skipConfirmation = false) {
            if (skipConfirmation || confirm('Are you sure you want to log out?')) {
                window.location.href = 'logout.php?confirm=1';
            }
        };
    </script>
</body>
</html>