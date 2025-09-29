<?php
/**
 * Database Configuration
 * 
 * Production-ready database connection with PDO, connection pooling,
 * and comprehensive error handling for the authentication system.
 * 
 * @author Sumit
 * @version 1.0
 */

// Prevent direct access
if (!defined('AUTH_SYSTEM')) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access denied.');
}

class DatabaseConfig {
    // Database connection parameters
    private const DB_HOST = 'localhost';
    private const DB_NAME = 'ecommerce_auth';
    private const DB_USER = 'root';
    private const DB_PASS = '';
    private const DB_CHARSET = 'utf8mb4';
    
    // Connection pool settings
    private const MAX_CONNECTIONS = 20;
    private const CONNECTION_TIMEOUT = 30;
    private const MAX_RETRIES = 3;
    
    // PDO options for security and performance
    private const PDO_OPTIONS = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => false, // Set to true for connection pooling
        PDO::ATTR_TIMEOUT => self::CONNECTION_TIMEOUT,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . self::DB_CHARSET,
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    ];
    
    private static $instance = null;
    private static $connection = null;
    private static $connectionCount = 0;
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private function __construct() {}
    
    /**
     * Get singleton instance
     * 
     * @return DatabaseConfig
     */
    public static function getInstance(): self {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Get database connection with automatic retry logic
     * 
     * @return PDO
     * @throws Exception
     */
    public static function getConnection(): PDO {
        if (self::$connection === null || !self::isConnectionAlive()) {
            self::createConnection();
        }
        
        return self::$connection;
    }
    
    /**
     * Create new database connection with retry mechanism
     * 
     * @throws Exception
     */
    private static function createConnection(): void {
        $retries = 0;
        $lastException = null;
        
        while ($retries < self::MAX_RETRIES) {
            try {
                // Check connection pool limit
                if (self::$connectionCount >= self::MAX_CONNECTIONS) {
                    throw new Exception('Maximum database connections reached');
                }
                
                $dsn = sprintf(
                    'mysql:host=%s;dbname=%s;charset=%s',
                    self::DB_HOST,
                    self::DB_NAME,
                    self::DB_CHARSET
                );
                
                self::$connection = new PDO($dsn, self::DB_USER, self::DB_PASS, self::PDO_OPTIONS);
                self::$connectionCount++;
                
                // Set additional MySQL-specific settings
                self::$connection->exec("SET sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''))");
                self::$connection->exec("SET time_zone = '+00:00'");
                
                // Connection successful
                self::logDatabaseEvent('connection_established', ['retry_count' => $retries]);
                return;
                
            } catch (PDOException $e) {
                $lastException = $e;
                $retries++;
                
                self::logDatabaseEvent('connection_failed', [
                    'retry_count' => $retries,
                    'error' => $e->getMessage(),
                    'error_code' => $e->getCode()
                ]);
                
                if ($retries < self::MAX_RETRIES) {
                    // Wait before retry (exponential backoff)
                    usleep(pow(2, $retries) * 100000); // 0.2s, 0.4s, 0.8s
                }
            }
        }
        
        // All retries failed
        throw new Exception(
            'Database connection failed after ' . self::MAX_RETRIES . ' attempts: ' . 
            $lastException->getMessage(),
            $lastException->getCode()
        );
    }
    
    /**
     * Check if connection is still alive
     * 
     * @return bool
     */
    private static function isConnectionAlive(): bool {
        if (self::$connection === null) {
            return false;
        }
        
        try {
            self::$connection->query('SELECT 1');
            return true;
        } catch (PDOException $e) {
            self::logDatabaseEvent('connection_lost', ['error' => $e->getMessage()]);
            return false;
        }
    }
    
    /**
     * Execute a prepared statement safely
     * 
     * @param string $query
     * @param array $params
     * @return PDOStatement
     * @throws Exception
     */
    public static function executeQuery(string $query, array $params = []): PDOStatement {
        try {
            $connection = self::getConnection();
            $stmt = $connection->prepare($query);
            $stmt->execute($params);
            
            return $stmt;
            
        } catch (PDOException $e) {
            self::logDatabaseEvent('query_error', [
                'query' => $query,
                'error' => $e->getMessage(),
                'error_code' => $e->getCode()
            ]);
            
            // Don't expose sensitive database information
            throw new Exception('Database query failed');
        }
    }
    
    /**
     * Get last insert ID
     * 
     * @return string
     */
    public static function getLastInsertId(): string {
        return self::getConnection()->lastInsertId();
    }
    
    /**
     * Start database transaction
     * 
     * @return bool
     */
    public static function beginTransaction(): bool {
        return self::getConnection()->beginTransaction();
    }
    
    /**
     * Commit database transaction
     * 
     * @return bool
     */
    public static function commit(): bool {
        return self::getConnection()->commit();
    }
    
    /**
     * Rollback database transaction
     * 
     * @return bool
     */
    public static function rollback(): bool {
        return self::getConnection()->rollBack();
    }
    
    /**
     * Close database connection
     */
    public static function closeConnection(): void {
        if (self::$connection !== null) {
            self::$connection = null;
            self::$connectionCount = max(0, self::$connectionCount - 1);
            self::logDatabaseEvent('connection_closed');
        }
    }
    
    /**
     * Log database events for monitoring
     * 
     * @param string $event
     * @param array $details
     */
    private static function logDatabaseEvent(string $event, array $details = []): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'details' => $details,
            'memory_usage' => memory_get_usage(true),
            'peak_memory' => memory_get_peak_usage(true)
        ];
        
        // In production, this should write to a proper logging system
        error_log('Database Event: ' . json_encode($logData));
    }
    
    /**
     * Get database statistics
     * 
     * @return array
     */
    public static function getStats(): array {
        return [
            'active_connections' => self::$connectionCount,
            'max_connections' => self::MAX_CONNECTIONS,
            'connection_timeout' => self::CONNECTION_TIMEOUT,
            'is_connected' => self::$connection !== null,
            'is_alive' => self::isConnectionAlive()
        ];
    }
    
    /**
     * Test database connection
     * 
     * @return array
     */
    public static function testConnection(): array {
        try {
            $start = microtime(true);
            $connection = self::getConnection();
            $stmt = $connection->query('SELECT VERSION() as version, NOW() as server_time');
            $result = $stmt->fetch();
            $duration = microtime(true) - $start;
            
            return [
                'status' => 'success',
                'version' => $result['version'],
                'server_time' => $result['server_time'],
                'connection_time' => round($duration * 1000, 2) . 'ms',
                'stats' => self::getStats()
            ];
            
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'error' => $e->getMessage(),
                'stats' => self::getStats()
            ];
        }
    }
}

// Environment-specific configuration (uncomment for production)
/*
if (getenv('ENVIRONMENT') === 'production') {
    // Production database configuration
    private const DB_HOST = getenv('DB_HOST') ?: 'localhost';
    private const DB_NAME = getenv('DB_NAME') ?: 'ecommerce_auth';
    private const DB_USER = getenv('DB_USER') ?: 'root';
    private const DB_PASS = getenv('DB_PASS') ?: '';
    
    // Enable SSL for production
    self::PDO_OPTIONS[PDO::MYSQL_ATTR_SSL_CA] = '/path/to/ca-cert.pem';
    self::PDO_OPTIONS[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
}
*/

// Register shutdown function to cleanup connections
register_shutdown_function(['DatabaseConfig', 'closeConnection']);

?>