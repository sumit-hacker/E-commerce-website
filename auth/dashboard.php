<?php
/**
 * User Dashboard
 * 
 * Protected dashboard showing user information and account management
 * 
 * @author Sumit
 * @version 1.0
 */

// Define constants
define('AUTH_SYSTEM', true);
define('PAGE_TITLE', 'Dashboard - E-Commerce Authentication');

// Include required files
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/session.php';

// Initialize session
SessionManager::init();

// Check if user is logged in
$loginCheck = SessionManager::isValidUserSession();
if (!$loginCheck['valid']) {
    // Redirect to login with return URL
    $currentUrl = urlencode($_SERVER['REQUEST_URI']);
    header('Location: login.php?redirect=' . $currentUrl);
    exit;
}

$user = $loginCheck['user'] ?? [];
$errors = [];
$success = false;
$message = '';

// Get additional user statistics
try {
    // Get user's login history
    $loginHistoryQuery = "
        SELECT event_type, ip_address, user_agent, created_at 
        FROM security_logs 
        WHERE user_id = ? AND event_type IN ('login_success', 'login_failed') 
        ORDER BY created_at DESC 
        LIMIT 10
    ";
    $loginHistoryStmt = DatabaseConfig::executeQuery($loginHistoryQuery, [$user['id']]);
    $loginHistory = $loginHistoryStmt->fetchAll();
    
    // Get active sessions
    $activeSessions = SessionManager::getUserActiveSessions($user['id']);
    
    // Get account statistics
    $statsQuery = "
        SELECT 
            (SELECT COUNT(*) FROM security_logs WHERE user_id = ? AND event_type = 'login_success') as total_logins,
            (SELECT COUNT(*) FROM security_logs WHERE user_id = ? AND event_type = 'login_failed') as failed_logins,
            (SELECT created_at FROM users WHERE id = ?) as account_created,
            (SELECT last_login FROM users WHERE id = ?) as last_login
    ";
    $statsStmt = DatabaseConfig::executeQuery($statsQuery, [$user['id'], $user['id'], $user['id'], $user['id']]);
    $stats = $statsStmt->fetch();
    
} catch (Exception $e) {
    $loginHistory = [];
    $activeSessions = [];
    $stats = [];
}

// Handle account actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $action = $_POST['action'] ?? '';
        $csrfToken = $_POST['csrf_token'] ?? '';
        
        if (!SecurityConfig::validateCSRFToken($csrfToken, 'dashboard_' . $action)) {
            throw new Exception('Invalid security token. Please try again.');
        }
        
        switch ($action) {
            case 'terminate_session':
                $sessionId = $_POST['session_id'] ?? '';
                if (!empty($sessionId)) {
                    $terminated = SessionManager::terminateUserSession($user['id'], $sessionId);
                    if ($terminated) {
                        $success = true;
                        $message = 'Session terminated successfully.';
                    } else {
                        $errors[] = 'Failed to terminate session.';
                    }
                }
                break;
                
            case 'terminate_all_sessions':
                $terminated = SessionManager::terminateOtherUserSessions($user['id']);
                $success = true;
                $message = "Terminated {$terminated} other session(s).";
                break;
                
            case 'update_profile':
                // Basic profile update (can be extended)
                $firstName = trim($_POST['first_name'] ?? '');
                $lastName = trim($_POST['last_name'] ?? '');
                $phone = trim($_POST['phone'] ?? '');
                
                // Validate inputs
                if (!empty($firstName)) {
                    $nameValidation = ValidationHelper::validate($firstName, 'name');
                    if (!$nameValidation['valid']) {
                        $errors = array_merge($errors, $nameValidation['errors']);
                    }
                }
                
                if (!empty($lastName)) {
                    $nameValidation = ValidationHelper::validate($lastName, 'name');
                    if (!$nameValidation['valid']) {
                        $errors = array_merge($errors, $nameValidation['errors']);
                    }
                }
                
                if (!empty($phone)) {
                    $phoneValidation = ValidationHelper::validate($phone, 'phone');
                    if (!$phoneValidation['valid']) {
                        $errors = array_merge($errors, $phoneValidation['errors']);
                    }
                }
                
                if (empty($errors)) {
                    $updateQuery = "UPDATE users SET first_name = ?, last_name = ?, phone = ? WHERE id = ?";
                    DatabaseConfig::executeQuery($updateQuery, [$firstName, $lastName, $phone, $user['id']]);
                    
                    // Update session data
                    $user['first_name'] = $firstName;
                    $user['last_name'] = $lastName;
                    
                    $success = true;
                    $message = 'Profile updated successfully.';
                }
                break;
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
        $errors[] = $e->getMessage();
        
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'errors' => [$e->getMessage()]
            ]);
            exit;
        }
    }
}

// Generate CSRF tokens
$sessionCsrfToken = SecurityConfig::generateCSRFToken('dashboard_terminate_session');
$allSessionsCsrfToken = SecurityConfig::generateCSRFToken('dashboard_terminate_all_sessions');
$profileCsrfToken = SecurityConfig::generateCSRFToken('dashboard_update_profile');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo PAGE_TITLE; ?></title>
    <meta name="description" content="Manage your e-commerce account, view security logs, and update your profile.">
    <meta name="robots" content="noindex, nofollow">
    
    <!-- Stylesheets -->
    <link rel="stylesheet" href="css/auth.css">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body style="background: #f8f9fa;">
    <div class="dashboard-container fade-in">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="user-info">
                <div class="user-avatar">
                    <?php echo strtoupper(substr($user['username'], 0, 2)); ?>
                </div>
                <div class="user-details">
                    <h2>Welcome, <?php echo htmlspecialchars($user['first_name'] ?: $user['username']); ?>!</h2>
                    <p><?php echo htmlspecialchars($user['email']); ?> • <?php echo ucfirst($user['role']); ?></p>
                </div>
            </div>
            <div>
                <a href="logout.php" class="btn btn-outline">Logout</a>
            </div>
        </div>
        
        <!-- Success/Error Messages -->
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <strong>Error!</strong>
                <?php foreach ($errors as $error): ?>
                    <div><?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <!-- Statistics Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3><?php echo $stats['total_logins'] ?? 0; ?></h3>
                <p>Total Logins</p>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                <h3><?php echo $stats['failed_logins'] ?? 0; ?></h3>
                <p>Failed Attempts</p>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);">
                <h3><?php echo count($activeSessions); ?></h3>
                <p>Active Sessions</p>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%);">
                <h3><?php echo $user['is_verified'] ? 'Verified' : 'Pending'; ?></h3>
                <p>Account Status</p>
            </div>
        </div>
        
        <!-- Main Content Tabs -->
        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" data-tab="profile">Profile</button>
                <button class="tab-button" data-tab="security">Security</button>
                <button class="tab-button" data-tab="sessions">Active Sessions</button>
                <button class="tab-button" data-tab="activity">Recent Activity</button>
            </div>
            
            <!-- Profile Tab -->
            <div class="tab-content active" id="tab-profile">
                <h3>Profile Information</h3>
                
                <form method="POST" action="dashboard.php" class="auth-form">
                    <input type="hidden" name="action" value="update_profile">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($profileCsrfToken); ?>">
                    
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" value="<?php echo htmlspecialchars($user['username']); ?>" disabled>
                        <small style="color: #666;">Username cannot be changed</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" value="<?php echo htmlspecialchars($user['email']); ?>" disabled>
                        <small style="color: #666;">Contact support to change email address</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="first_name">First Name</label>
                        <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($user['first_name'] ?? ''); ?>" maxlength="100">
                    </div>
                    
                    <div class="form-group">
                        <label for="last_name">Last Name</label>
                        <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($user['last_name'] ?? ''); ?>" maxlength="100">
                    </div>
                    
                    <div class="form-group">
                        <label for="phone">Phone Number</label>
                        <input type="tel" id="phone" name="phone" value="<?php echo htmlspecialchars($user['phone'] ?? ''); ?>" maxlength="20">
                    </div>
                    
                    <div class="form-group">
                        <label>Account Created</label>
                        <input type="text" value="<?php echo date('F j, Y', strtotime($stats['account_created'] ?? 'now')); ?>" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label>Last Login</label>
                        <input type="text" value="<?php echo $stats['last_login'] ? date('F j, Y g:i A', strtotime($stats['last_login'])) : 'Never'; ?>" disabled>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>
            
            <!-- Security Tab -->
            <div class="tab-content" id="tab-security">
                <h3>Security Settings</h3>
                
                <div class="alert alert-info">
                    <strong>🔒 Account Security</strong>
                    <ul style="margin: 10px 0 0 20px;">
                        <li>Password last changed: Recently</li>
                        <li>Two-factor authentication: Not enabled</li>
                        <li>Email verification: <?php echo $user['is_verified'] ? 'Verified ✅' : 'Pending ⚠️'; ?></li>
                        <li>Account status: <?php echo $user['is_active'] ? 'Active ✅' : 'Inactive ❌'; ?></li>
                    </ul>
                </div>
                
                <div class="security-actions" style="display: flex; gap: 15px; flex-wrap: wrap; margin-top: 20px;">
                    <a href="reset-password.php" class="btn btn-outline">Change Password</a>
                    <?php if (!$user['is_verified']): ?>
                        <a href="verify.php" class="btn btn-warning">Verify Email</a>
                    <?php endif; ?>
                    <button class="btn btn-danger" onclick="terminateAllSessions()">End All Sessions</button>
                </div>
                
                <h4 style="margin-top: 30px;">Security Recommendations</h4>
                <div class="alert alert-warning">
                    <ul style="margin: 0 0 0 20px;">
                        <li>Use a strong, unique password</li>
                        <li>Enable two-factor authentication (coming soon)</li>
                        <li>Regularly review your active sessions</li>
                        <li>Don't share your account credentials</li>
                        <li>Log out from shared computers</li>
                    </ul>
                </div>
            </div>
            
            <!-- Active Sessions Tab -->
            <div class="tab-content" id="tab-sessions">
                <h3>Active Sessions</h3>
                
                <?php if (!empty($activeSessions)): ?>
                    <div class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Device</th>
                                    <th>IP Address</th>
                                    <th>Last Activity</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($activeSessions as $session): ?>
                                    <tr>
                                        <td>
                                            <strong><?php echo $session['session_id'] === session_id() ? 'This Device' : 'Other Device'; ?></strong><br>
                                            <small><?php echo htmlspecialchars(substr($session['user_agent'], 0, 50)) . '...'; ?></small>
                                        </td>
                                        <td><?php echo htmlspecialchars($session['ip_address']); ?></td>
                                        <td><?php echo date('M j, Y g:i A', strtotime($session['last_activity'])); ?></td>
                                        <td>
                                            <?php if ($session['session_id'] !== session_id()): ?>
                                                <button class="btn btn-danger" style="padding: 5px 10px; font-size: 0.85rem;" 
                                                        onclick="terminateSession('<?php echo htmlspecialchars($session['session_id']); ?>')">
                                                    End Session
                                                </button>
                                            <?php else: ?>
                                                <span class="text-muted">Current</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <button class="btn btn-danger" onclick="terminateAllSessions()">End All Other Sessions</button>
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">
                        <strong>No Active Sessions</strong><br>
                        You don't have any other active sessions.
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Recent Activity Tab -->
            <div class="tab-content" id="tab-activity">
                <h3>Recent Activity</h3>
                
                <?php if (!empty($loginHistory)): ?>
                    <div class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Event</th>
                                    <th>IP Address</th>
                                    <th>Date</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($loginHistory as $log): ?>
                                    <tr>
                                        <td>
                                            <strong><?php echo ucwords(str_replace('_', ' ', $log['event_type'])); ?></strong><br>
                                            <small><?php echo htmlspecialchars(substr($log['user_agent'], 0, 40)) . '...'; ?></small>
                                        </td>
                                        <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                        <td><?php echo date('M j, Y g:i A', strtotime($log['created_at'])); ?></td>
                                        <td>
                                            <span class="status-badge status-<?php echo $log['event_type'] === 'login_success' ? 'success' : 'danger'; ?>">
                                                <?php echo $log['event_type'] === 'login_success' ? 'Success' : 'Failed'; ?>
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">
                        <strong>No Recent Activity</strong><br>
                        No login activity to display.
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef;">
            <h4>Quick Actions</h4>
            <div style="display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px;">
                <a href="/" class="btn btn-outline">Return to Store</a>
                <a href="/orders" class="btn btn-outline">View Orders</a>
                <a href="/profile" class="btn btn-outline">Edit Profile</a>
                <a href="/support" class="btn btn-outline">Contact Support</a>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="js/auth.js"></script>
    
    <!-- Dashboard-specific styles -->
    <style>
        .tab-container {
            margin-top: 30px;
        }
        
        .tab-buttons {
            display: flex;
            border-bottom: 2px solid #e9ecef;
            margin-bottom: 20px;
            overflow-x: auto;
        }
        
        .tab-button {
            background: none;
            border: none;
            padding: 15px 20px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            color: #666;
            border-bottom: 2px solid transparent;
            transition: all 0.3s ease;
            white-space: nowrap;
        }
        
        .tab-button:hover {
            color: #667eea;
            background: #f8f9fa;
        }
        
        .tab-button.active {
            color: #667eea;
            border-bottom-color: #667eea;
            background: #f8f9fa;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-success {
            background: #d4edda;
            color: #155724;
        }
        
        .status-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        @media (max-width: 768px) {
            .dashboard-header {
                flex-direction: column;
                text-align: center;
                gap: 20px;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
            
            .security-actions {
                flex-direction: column;
            }
            
            .security-actions .btn {
                width: 100%;
            }
        }
    </style>
    
    <!-- Dashboard JavaScript -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Tab functionality
            const tabButtons = document.querySelectorAll('.tab-button');
            const tabContents = document.querySelectorAll('.tab-content');
            
            tabButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const targetTab = this.dataset.tab;
                    
                    // Remove active class from all buttons and contents
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    tabContents.forEach(content => content.classList.remove('active'));
                    
                    // Add active class to clicked button and corresponding content
                    this.classList.add('active');
                    document.getElementById('tab-' + targetTab).classList.add('active');
                });
            });
            
            // Auto-refresh session data every 30 seconds
            setInterval(function() {
                // You can implement auto-refresh here if needed
                console.log('Session check...');
            }, 30000);
        });
        
        // Session management functions
        function terminateSession(sessionId) {
            if (confirm('Are you sure you want to end this session?')) {
                const formData = new FormData();
                formData.append('action', 'terminate_session');
                formData.append('session_id', sessionId);
                formData.append('csrf_token', '<?php echo htmlspecialchars($sessionCsrfToken); ?>');
                
                fetch('dashboard.php', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        window.AuthUtils.showAlert(data.message, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        window.AuthUtils.showAlert(data.errors.join(', '), 'error');
                    }
                })
                .catch(error => {
                    window.AuthUtils.showAlert('An error occurred', 'error');
                });
            }
        }
        
        function terminateAllSessions() {
            if (confirm('Are you sure you want to end all other sessions? This will log out all your other devices.')) {
                const formData = new FormData();
                formData.append('action', 'terminate_all_sessions');
                formData.append('csrf_token', '<?php echo htmlspecialchars($allSessionsCsrfToken); ?>');
                
                fetch('dashboard.php', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        window.AuthUtils.showAlert(data.message, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        window.AuthUtils.showAlert(data.errors.join(', '), 'error');
                    }
                })
                .catch(error => {
                    window.AuthUtils.showAlert('An error occurred', 'error');
                });
            }
        }
    </script>
</body>
</html>