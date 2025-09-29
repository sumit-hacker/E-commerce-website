<?php
/**
 * Availability Check API
 * 
 * AJAX endpoint for checking username and email availability
 * 
 * @author Sumit
 * @version 1.0
 */

define('AUTH_SYSTEM', true);

// Include required files
require_once __DIR__ . '/includes/functions.php';

// Set JSON content type
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Only allow AJAX requests
if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    http_response_code(403);
    echo json_encode(['error' => 'Direct access not allowed']);
    exit;
}

try {
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || !isset($input['type']) || !isset($input['value'])) {
        throw new Exception('Invalid request data');
    }
    
    $type = $input['type'];
    $value = trim($input['value']);
    
    if (empty($value)) {
        echo json_encode(['available' => null]);
        exit;
    }
    
    $available = false;
    
    switch ($type) {
        case 'username':
            // Validate username format first
            $validation = ValidationHelper::validate($value, 'username');
            if (!$validation['valid']) {
                echo json_encode(['available' => false, 'reason' => 'invalid_format']);
                exit;
            }
            
            // Check if username exists
            $query = "SELECT id FROM users WHERE username = ?";
            $stmt = DatabaseConfig::executeQuery($query, [$value]);
            $available = !$stmt->fetch();
            break;
            
        case 'email':
            // Validate email format first
            $validation = ValidationHelper::validate($value, 'email');
            if (!$validation['valid']) {
                echo json_encode(['available' => false, 'reason' => 'invalid_format']);
                exit;
            }
            
            // Check if email exists
            $query = "SELECT id FROM users WHERE email = ?";
            $stmt = DatabaseConfig::executeQuery($query, [strtolower($value)]);
            $available = !$stmt->fetch();
            break;
            
        default:
            throw new Exception('Invalid check type');
    }
    
    echo json_encode(['available' => $available]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Check failed']);
    error_log('Availability check error: ' . $e->getMessage());
}
?>