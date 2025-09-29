<?php
/**
 * Input Validation and Sanitization
 * 
 * Comprehensive input validation, sanitization, and security checks
 * for the authentication system with XSS and injection protection.
 * 
 * @author Sumit
 * @version 1.0
 */

// Define AUTH_SYSTEM constant to allow config files to load
define('AUTH_SYSTEM', true);

// Include required configuration
require_once __DIR__ . '/../config/security.php';

class ValidationHelper {
    
    // Common validation patterns
    private const PATTERNS = [
        'username' => '/^[a-zA-Z0-9_.-]{3,30}$/',
        'email' => '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
        'name' => '/^[a-zA-Z\s\'-]{1,100}$/u',
        'phone' => '/^[\d\s\-\+\(\)]{10,20}$/',
        'alphanumeric' => '/^[a-zA-Z0-9]+$/',
        'alpha' => '/^[a-zA-Z]+$/',
        'numeric' => '/^[0-9]+$/',
        'url' => '/^https?:\/\/[^\s\/$.?#].[^\s]*$/i',
        'ip' => '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/',
        'mac_address' => '/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/',
        'credit_card' => '/^[0-9]{13,19}$/',
        'postal_code' => '/^[0-9]{5,10}$/',
        'date' => '/^\d{4}-\d{2}-\d{2}$/',
        'datetime' => '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
        'time' => '/^\d{2}:\d{2}:\d{2}$/',
        'slug' => '/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
        'hex_color' => '/^#[0-9A-Fa-f]{6}$/',
        'uuid' => '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i'
    ];
    
    // Dangerous patterns to detect
    private const DANGEROUS_PATTERNS = [
        'sql_injection' => [
            '/(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bcreate\b|\balter\b)/i',
            '/(\bor\b|\band\b)\s+\d+\s*=\s*\d+/i',
            '/[\'";]/',
            '/\-\-/',
            '/\/\*.*\*\//',
            '/\bexec\b|\bexecute\b/i'
        ],
        'xss' => [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi',
            '/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onclick\s*=/i',
            '/onerror\s*=/i',
            '/onmouseover\s*=/i'
        ],
        'file_inclusion' => [
            '/\.\.[\/\\\\]/i',
            '/\.(php|asp|jsp|py|rb|pl|cgi)[0-9]*/i',
            '/\/etc\/passwd/i',
            '/\/proc\/self\/environ/i',
            '/file:\/\//i'
        ],
        'command_injection' => [
            '/[\|;&$`><]/i',
            '/\b(cat|ls|pwd|id|whoami|uname|ps|netstat|ifconfig|wget|curl|nc|ncat|telnet|ssh)\b/i'
        ]
    ];
    
    /**
     * Validate and sanitize input data
     * 
     * @param mixed $data Input data to validate
     * @param string $type Type of validation to perform
     * @param array $options Additional validation options
     * @return array Validation result
     */
    public static function validate($data, string $type, array $options = []): array {
        $result = [
            'valid' => true,
            'sanitized' => $data,
            'errors' => [],
            'warnings' => []
        ];
        
        // Handle null or empty data
        if ($data === null || $data === '') {
            if ($options['required'] ?? false) {
                $result['valid'] = false;
                $result['errors'][] = ucfirst($type) . ' is required';
            }
            return $result;
        }
        
        // Convert to string for validation
        $stringData = is_array($data) ? json_encode($data) : (string)$data;
        
        // Check for dangerous patterns first
        $securityCheck = self::checkSecurity($stringData);
        if (!$securityCheck['safe']) {
            $result['valid'] = false;
            $result['errors'] = array_merge($result['errors'], $securityCheck['threats']);
            return $result;
        }
        
        // Perform type-specific validation
        switch ($type) {
            case 'username':
                $result = self::validateUsername($stringData, $options);
                break;
            case 'email':
                $result = self::validateEmail($stringData, $options);
                break;
            case 'password':
                $result = self::validatePassword($stringData, $options);
                break;
            case 'name':
                $result = self::validateName($stringData, $options);
                break;
            case 'phone':
                $result = self::validatePhone($stringData, $options);
                break;
            case 'url':
                $result = self::validateUrl($stringData, $options);
                break;
            case 'date':
                $result = self::validateDate($stringData, $options);
                break;
            case 'number':
                $result = self::validateNumber($stringData, $options);
                break;
            case 'file':
                $result = self::validateFile($data, $options);
                break;
            case 'json':
                $result = self::validateJson($stringData, $options);
                break;
            case 'array':
                $result = self::validateArray($data, $options);
                break;
            case 'text':
            default:
                $result = self::validateText($stringData, $options);
                break;
        }
        
        return $result;
    }
    
    /**
     * Sanitize input to prevent XSS and other attacks
     * 
     * @param string $input
     * @param array $options
     * @return string
     */
    public static function sanitize(string $input, array $options = []): string {
        // Remove null bytes
        $input = str_replace("\0", "", $input);
        
        // Normalize line endings
        $input = str_replace(["\r\n", "\r"], "\n", $input);
        
        // Trim whitespace
        $input = trim($input);
        
        // Handle encoding
        if ($options['fix_encoding'] ?? true) {
            $input = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
        }
        
        // Remove or escape HTML
        if ($options['allow_html'] ?? false) {
            // Allow limited HTML tags
            $allowedTags = $options['allowed_tags'] ?? '<p><br><strong><em><u><a>';
            $input = strip_tags($input, $allowedTags);
            
            // Sanitize attributes
            $input = self::sanitizeHtmlAttributes($input);
        } else {
            // Remove all HTML
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        // Limit length
        $maxLength = $options['max_length'] ?? SecurityConfig::MAX_INPUT_LENGTH;
        if (strlen($input) > $maxLength) {
            $input = mb_substr($input, 0, $maxLength, 'UTF-8');
        }
        
        return $input;
    }
    
    /**
     * Validate multiple fields at once
     * 
     * @param array $data
     * @param array $rules
     * @return array
     */
    public static function validateMultiple(array $data, array $rules): array {
        $results = [
            'valid' => true,
            'errors' => [],
            'sanitized' => [],
            'warnings' => []
        ];
        
        foreach ($rules as $field => $rule) {
            $fieldData = $data[$field] ?? null;
            $fieldResult = self::validate($fieldData, $rule['type'], $rule['options'] ?? []);
            
            $results['sanitized'][$field] = $fieldResult['sanitized'];
            
            if (!$fieldResult['valid']) {
                $results['valid'] = false;
                $results['errors'][$field] = $fieldResult['errors'];
            }
            
            if (!empty($fieldResult['warnings'])) {
                $results['warnings'][$field] = $fieldResult['warnings'];
            }
        }
        
        return $results;
    }
    
    // ========== SPECIFIC VALIDATORS ==========
    
    /**
     * Validate username
     */
    private static function validateUsername(string $username, array $options): array {
        $result = ['valid' => true, 'sanitized' => $username, 'errors' => [], 'warnings' => []];
        
        // Basic pattern check
        if (!preg_match(self::PATTERNS['username'], $username)) {
            $result['valid'] = false;
            $result['errors'][] = 'Username must be 3-30 characters long and contain only letters, numbers, dots, hyphens, and underscores';
        }
        
        // Check for reserved words
        $reserved = ['admin', 'root', 'user', 'test', 'guest', 'anonymous', 'www', 'mail', 'ftp', 'api'];
        if (in_array(strtolower($username), $reserved)) {
            $result['valid'] = false;
            $result['errors'][] = 'Username is reserved and cannot be used';
        }
        
        // Check for consecutive special characters
        if (preg_match('/[._-]{2,}/', $username)) {
            $result['valid'] = false;
            $result['errors'][] = 'Username cannot contain consecutive special characters';
        }
        
        // Cannot start or end with special characters
        if (preg_match('/^[._-]|[._-]$/', $username)) {
            $result['valid'] = false;
            $result['errors'][] = 'Username cannot start or end with special characters';
        }
        
        $result['sanitized'] = strtolower(trim($username));
        return $result;
    }
    
    /**
     * Validate email address
     */
    private static function validateEmail(string $email, array $options): array {
        $result = ['valid' => true, 'sanitized' => $email, 'errors' => [], 'warnings' => []];
        
        // Basic validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $result['valid'] = false;
            $result['errors'][] = 'Invalid email address format';
        }
        
        // Length check
        if (strlen($email) > 255) {
            $result['valid'] = false;
            $result['errors'][] = 'Email address is too long (maximum 255 characters)';
        }
        
        // Check for dangerous patterns
        if (preg_match('/[<>"\']/', $email)) {
            $result['valid'] = false;
            $result['errors'][] = 'Email address contains invalid characters';
        }
        
        // Domain validation
        $parts = explode('@', $email);
        if (count($parts) == 2) {
            $domain = $parts[1];
            
            // Check domain format
            if (!preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain)) {
                $result['valid'] = false;
                $result['errors'][] = 'Invalid email domain format';
            }
            
            // Check for suspicious domains (optional)
            $suspiciousDomains = ['10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
            if (in_array(strtolower($domain), $suspiciousDomains)) {
                $result['warnings'][] = 'Temporary email service detected';
            }
        }
        
        $result['sanitized'] = strtolower(trim($email));
        return $result;
    }
    
    /**
     * Validate password
     */
    private static function validatePassword(string $password, array $options): array {
        return SecurityConfig::validatePassword($password);
    }
    
    /**
     * Validate name (first name, last name)
     */
    private static function validateName(string $name, array $options): array {
        $result = ['valid' => true, 'sanitized' => $name, 'errors' => [], 'warnings' => []];
        
        // Basic pattern check
        if (!preg_match(self::PATTERNS['name'], $name)) {
            $result['valid'] = false;
            $result['errors'][] = 'Name contains invalid characters (only letters, spaces, hyphens, and apostrophes allowed)';
        }
        
        // Length check
        $minLength = $options['min_length'] ?? 1;
        $maxLength = $options['max_length'] ?? 100;
        
        if (strlen($name) < $minLength) {
            $result['valid'] = false;
            $result['errors'][] = "Name must be at least {$minLength} characters";
        }
        
        if (strlen($name) > $maxLength) {
            $result['valid'] = false;
            $result['errors'][] = "Name cannot exceed {$maxLength} characters";
        }
        
        // Check for repeated characters
        if (preg_match('/(.)\1{3,}/', $name)) {
            $result['valid'] = false;
            $result['errors'][] = 'Name cannot contain more than 3 consecutive identical characters';
        }
        
        $result['sanitized'] = trim($name);
        return $result;
    }
    
    /**
     * Validate phone number
     */
    private static function validatePhone(string $phone, array $options): array {
        $result = ['valid' => true, 'sanitized' => $phone, 'errors' => [], 'warnings' => []];
        
        // Clean phone number
        $cleaned = preg_replace('/[^\d+]/', '', $phone);
        
        // Basic length check
        if (strlen($cleaned) < 10 || strlen($cleaned) > 15) {
            $result['valid'] = false;
            $result['errors'][] = 'Phone number must be 10-15 digits';
        }
        
        // Pattern validation
        if (!preg_match(self::PATTERNS['phone'], $phone)) {
            $result['valid'] = false;
            $result['errors'][] = 'Invalid phone number format';
        }
        
        $result['sanitized'] = $cleaned;
        return $result;
    }
    
    /**
     * Validate URL
     */
    private static function validateUrl(string $url, array $options): array {
        $result = ['valid' => true, 'sanitized' => $url, 'errors' => [], 'warnings' => []];
        
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $result['valid'] = false;
            $result['errors'][] = 'Invalid URL format';
        }
        
        // Check protocol
        $allowedProtocols = $options['protocols'] ?? ['http', 'https'];
        $protocol = parse_url($url, PHP_URL_SCHEME);
        
        if (!in_array($protocol, $allowedProtocols)) {
            $result['valid'] = false;
            $result['errors'][] = 'URL protocol not allowed';
        }
        
        $result['sanitized'] = filter_var($url, FILTER_SANITIZE_URL);
        return $result;
    }
    
    /**
     * Validate date
     */
    private static function validateDate(string $date, array $options): array {
        $result = ['valid' => true, 'sanitized' => $date, 'errors' => [], 'warnings' => []];
        
        $format = $options['format'] ?? 'Y-m-d';
        $dateTime = DateTime::createFromFormat($format, $date);
        
        if (!$dateTime || $dateTime->format($format) !== $date) {
            $result['valid'] = false;
            $result['errors'][] = "Invalid date format (expected: {$format})";
        }
        
        // Check date range
        if (isset($options['min_date'])) {
            $minDate = new DateTime($options['min_date']);
            if ($dateTime < $minDate) {
                $result['valid'] = false;
                $result['errors'][] = 'Date is too early';
            }
        }
        
        if (isset($options['max_date'])) {
            $maxDate = new DateTime($options['max_date']);
            if ($dateTime > $maxDate) {
                $result['valid'] = false;
                $result['errors'][] = 'Date is too late';
            }
        }
        
        return $result;
    }
    
    /**
     * Validate number
     */
    private static function validateNumber($number, array $options): array {
        $result = ['valid' => true, 'sanitized' => $number, 'errors' => [], 'warnings' => []];
        
        if (!is_numeric($number)) {
            $result['valid'] = false;
            $result['errors'][] = 'Value must be a number';
            return $result;
        }
        
        $number = (float)$number;
        
        // Range validation
        if (isset($options['min']) && $number < $options['min']) {
            $result['valid'] = false;
            $result['errors'][] = "Number must be at least {$options['min']}";
        }
        
        if (isset($options['max']) && $number > $options['max']) {
            $result['valid'] = false;
            $result['errors'][] = "Number cannot exceed {$options['max']}";
        }
        
        // Integer validation
        if (($options['integer'] ?? false) && !is_int($number)) {
            $result['valid'] = false;
            $result['errors'][] = 'Value must be an integer';
        }
        
        $result['sanitized'] = $number;
        return $result;
    }
    
    /**
     * Validate file upload
     */
    private static function validateFile($file, array $options): array {
        $result = ['valid' => true, 'sanitized' => $file, 'errors' => [], 'warnings' => []];
        
        if (!is_array($file) || !isset($file['tmp_name'])) {
            $result['valid'] = false;
            $result['errors'][] = 'Invalid file upload';
            return $result;
        }
        
        // Check upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $result['valid'] = false;
            $result['errors'][] = 'File upload error: ' . self::getUploadErrorMessage($file['error']);
            return $result;
        }
        
        // File size validation
        $maxSize = $options['max_size'] ?? SecurityConfig::MAX_UPLOAD_SIZE;
        if ($file['size'] > $maxSize) {
            $result['valid'] = false;
            $result['errors'][] = 'File size exceeds maximum allowed size';
        }
        
        // File type validation
        $allowedTypes = $options['allowed_types'] ?? SecurityConfig::ALLOWED_FILE_TYPES;
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!in_array($fileExtension, $allowedTypes)) {
            $result['valid'] = false;
            $result['errors'][] = 'File type not allowed';
        }
        
        // MIME type validation
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $allowedMimes = $options['allowed_mimes'] ?? [
            'image/jpeg', 'image/png', 'image/gif', 'application/pdf',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        
        if (!in_array($mimeType, $allowedMimes)) {
            $result['valid'] = false;
            $result['errors'][] = 'File MIME type not allowed';
        }
        
        return $result;
    }
    
    /**
     * Validate JSON
     */
    private static function validateJson(string $json, array $options): array {
        $result = ['valid' => true, 'sanitized' => $json, 'errors' => [], 'warnings' => []];
        
        $decoded = json_decode($json, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $result['valid'] = false;
            $result['errors'][] = 'Invalid JSON format: ' . json_last_error_msg();
            return $result;
        }
        
        // Schema validation (basic)
        if (isset($options['schema']) && is_array($options['schema'])) {
            $schemaValidation = self::validateJsonSchema($decoded, $options['schema']);
            if (!$schemaValidation['valid']) {
                $result['valid'] = false;
                $result['errors'] = array_merge($result['errors'], $schemaValidation['errors']);
            }
        }
        
        $result['sanitized'] = $decoded;
        return $result;
    }
    
    /**
     * Validate array
     */
    private static function validateArray($array, array $options): array {
        $result = ['valid' => true, 'sanitized' => $array, 'errors' => [], 'warnings' => []];
        
        if (!is_array($array)) {
            $result['valid'] = false;
            $result['errors'][] = 'Value must be an array';
            return $result;
        }
        
        // Size validation
        $minSize = $options['min_size'] ?? 0;
        $maxSize = $options['max_size'] ?? 1000;
        
        if (count($array) < $minSize) {
            $result['valid'] = false;
            $result['errors'][] = "Array must have at least {$minSize} items";
        }
        
        if (count($array) > $maxSize) {
            $result['valid'] = false;
            $result['errors'][] = "Array cannot have more than {$maxSize} items";
        }
        
        // Validate array elements
        if (isset($options['element_type'])) {
            $sanitizedArray = [];
            foreach ($array as $key => $value) {
                $elementResult = self::validate($value, $options['element_type'], $options['element_options'] ?? []);
                if (!$elementResult['valid']) {
                    $result['valid'] = false;
                    $result['errors'][] = "Invalid array element at index {$key}";
                }
                $sanitizedArray[$key] = $elementResult['sanitized'];
            }
            $result['sanitized'] = $sanitizedArray;
        }
        
        return $result;
    }
    
    /**
     * Validate text
     */
    private static function validateText(string $text, array $options): array {
        $result = ['valid' => true, 'sanitized' => $text, 'errors' => [], 'warnings' => []];
        
        // Length validation
        $minLength = $options['min_length'] ?? 0;
        $maxLength = $options['max_length'] ?? SecurityConfig::MAX_INPUT_LENGTH;
        
        if (strlen($text) < $minLength) {
            $result['valid'] = false;
            $result['errors'][] = "Text must be at least {$minLength} characters";
        }
        
        if (strlen($text) > $maxLength) {
            $result['valid'] = false;
            $result['errors'][] = "Text cannot exceed {$maxLength} characters";
        }
        
        // Pattern validation
        if (isset($options['pattern'])) {
            if (!preg_match($options['pattern'], $text)) {
                $result['valid'] = false;
                $result['errors'][] = 'Text format is invalid';
            }
        }
        
        $result['sanitized'] = self::sanitize($text, $options);
        return $result;
    }
    
    // ========== SECURITY FUNCTIONS ==========
    
    /**
     * Check input for security threats
     */
    private static function checkSecurity(string $input): array {
        $threats = [];
        
        foreach (self::DANGEROUS_PATTERNS as $threatType => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $input)) {
                    $threats[] = "Potential {$threatType} detected";
                    break; // Only report each threat type once
                }
            }
        }
        
        return [
            'safe' => empty($threats),
            'threats' => $threats
        ];
    }
    
    /**
     * Sanitize HTML attributes
     */
    private static function sanitizeHtmlAttributes(string $html): string {
        // Remove dangerous attributes
        $dangerousAttrs = ['onload', 'onclick', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
        
        foreach ($dangerousAttrs as $attr) {
            $html = preg_replace('/' . $attr . '\s*=\s*["\'][^"\']*["\']/i', '', $html);
        }
        
        // Remove javascript: and vbscript: protocols
        $html = preg_replace('/(javascript|vbscript):/i', '', $html);
        
        return $html;
    }
    
    /**
     * Get upload error message
     */
    private static function getUploadErrorMessage(int $errorCode): string {
        switch ($errorCode) {
            case UPLOAD_ERR_INI_SIZE:
                return 'File exceeds upload_max_filesize directive';
            case UPLOAD_ERR_FORM_SIZE:
                return 'File exceeds MAX_FILE_SIZE directive';
            case UPLOAD_ERR_PARTIAL:
                return 'File was only partially uploaded';
            case UPLOAD_ERR_NO_FILE:
                return 'No file was uploaded';
            case UPLOAD_ERR_NO_TMP_DIR:
                return 'Missing temporary folder';
            case UPLOAD_ERR_CANT_WRITE:
                return 'Failed to write file to disk';
            case UPLOAD_ERR_EXTENSION:
                return 'File upload stopped by extension';
            default:
                return 'Unknown upload error';
        }
    }
    
    /**
     * Basic JSON schema validation
     */
    private static function validateJsonSchema(array $data, array $schema): array {
        $errors = [];
        
        foreach ($schema as $field => $rules) {
            if (isset($rules['required']) && $rules['required'] && !isset($data[$field])) {
                $errors[] = "Required field '{$field}' is missing";
                continue;
            }
            
            if (isset($data[$field])) {
                $value = $data[$field];
                
                // Type validation
                if (isset($rules['type'])) {
                    $expectedType = $rules['type'];
                    $actualType = gettype($value);
                    
                    if ($expectedType === 'integer' && $actualType !== 'integer') {
                        $errors[] = "Field '{$field}' must be an integer";
                    } elseif ($expectedType === 'string' && $actualType !== 'string') {
                        $errors[] = "Field '{$field}' must be a string";
                    } elseif ($expectedType === 'array' && $actualType !== 'array') {
                        $errors[] = "Field '{$field}' must be an array";
                    }
                }
                
                // Length validation for strings
                if (is_string($value)) {
                    if (isset($rules['min_length']) && strlen($value) < $rules['min_length']) {
                        $errors[] = "Field '{$field}' is too short";
                    }
                    if (isset($rules['max_length']) && strlen($value) > $rules['max_length']) {
                        $errors[] = "Field '{$field}' is too long";
                    }
                }
            }
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
    
    /**
     * Generate validation rules for common use cases
     */
    public static function getCommonRules(): array {
        return [
            'registration' => [
                'username' => ['type' => 'username', 'options' => ['required' => true]],
                'email' => ['type' => 'email', 'options' => ['required' => true]],
                'password' => ['type' => 'password', 'options' => ['required' => true]],
                'first_name' => ['type' => 'name', 'options' => ['required' => false]],
                'last_name' => ['type' => 'name', 'options' => ['required' => false]],
                'phone' => ['type' => 'phone', 'options' => ['required' => false]]
            ],
            'login' => [
                'username' => ['type' => 'text', 'options' => ['required' => true, 'max_length' => 255]],
                'password' => ['type' => 'text', 'options' => ['required' => true, 'max_length' => 128]]
            ],
            'password_reset' => [
                'email' => ['type' => 'email', 'options' => ['required' => true]]
            ],
            'new_password' => [
                'password' => ['type' => 'password', 'options' => ['required' => true]],
                'confirm_password' => ['type' => 'password', 'options' => ['required' => true]]
            ]
        ];
    }
}

?>