<?php
/**
 * Phase 2 Security Helpers for Silent Auction Manager
 * Provides encryption, audit logging, rate limiting, and validation functions
 */

// ═════════════════════════════════════════════════════════════════════════════
// ENCRYPTION/DECRYPTION - AES-256-CBC
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Encrypt plaintext using AES-256-CBC
 * @param string $plaintext Data to encrypt
 * @param string $encryptionKey Encryption key from environment
 * @return string Base64-encoded ciphertext with IV prepended
 */
function encryptData($plaintext, $encryptionKey) {
    if (empty($plaintext)) {
        return null;
    }

    // Use SHA-256 to derive a consistent 32-byte key
    $key = hash('sha256', $encryptionKey, true);

    // Generate random IV
    $iv = openssl_random_pseudo_bytes(16);

    // Encrypt data
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

    // Return IV + encrypted data, base64 encoded for storage
    return base64_encode($iv . $encrypted);
}

/**
 * Decrypt AES-256-CBC encrypted data
 * @param string $ciphertext Base64-encoded ciphertext with IV prepended
 * @param string $encryptionKey Encryption key from environment
 * @return string|null Plaintext, or null if decryption fails
 */
function decryptData($ciphertext, $encryptionKey) {
    if (empty($ciphertext)) {
        return null;
    }

    // Decode from base64
    $decoded = base64_decode($ciphertext, true);
    if ($decoded === false) {
        return null;
    }

    // Extract IV (first 16 bytes)
    $iv = substr($decoded, 0, 16);
    $encrypted = substr($decoded, 16);

    // Use SHA-256 to derive consistent key
    $key = hash('sha256', $encryptionKey, true);

    // Decrypt
    $plaintext = openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

    return $plaintext;
}

/**
 * Check if a value appears to be encrypted (base64-encoded with length > 50)
 */
function isEncrypted($value) {
    if (empty($value) || !is_string($value)) {
        return false;
    }

    // Encrypted values are base64, typically > 50 chars
    if (strlen($value) < 50) {
        return false;
    }

    // Check if it's valid base64
    if (base64_encode(base64_decode($value, true)) !== $value) {
        return false;
    }

    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// AUDIT LOGGING
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Log an audit event to database and file
 * @param PDO $pdo Database connection
 * @param string $userId User ID (from session)
 * @param string $action Action being logged (e.g., 'save_winners', 'delete_item')
 * @param string $tableAffected Table name affected
 * @param string|int $recordId Record ID affected
 * @param mixed $oldValue Old value (null for inserts)
 * @param mixed $newValue New value (null for deletes)
 * @param string $status 'success' or 'failure'
 * @param string $details Additional details
 */
function logAudit($pdo, $userId, $action, $tableAffected, $recordId, $oldValue, $newValue, $status = 'success', $details = '') {
    try {
        // Create audit_log table if it doesn't exist
        $pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (
            audit_id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(255),
            action VARCHAR(100),
            table_affected VARCHAR(100),
            record_id VARCHAR(255),
            old_value LONGTEXT,
            new_value LONGTEXT,
            ip_address VARCHAR(45),
            status VARCHAR(20),
            details LONGTEXT,
            INDEX idx_timestamp (timestamp),
            INDEX idx_user_action (user_id, action),
            INDEX idx_record (table_affected, record_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Get client IP
        $ip = getClientIp();

        // Prepare audit entry
        $query = "INSERT INTO audit_log
                  (user_id, action, table_affected, record_id, old_value, new_value, ip_address, status, details)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $pdo->prepare($query);
        $stmt->execute([
            $userId ?? 'system',
            $action,
            $tableAffected,
            (string)$recordId,
            is_array($oldValue) || is_object($oldValue) ? json_encode($oldValue) : (string)$oldValue,
            is_array($newValue) || is_object($newValue) ? json_encode($newValue) : (string)$newValue,
            $ip,
            $status,
            $details
        ]);
    } catch (Exception $e) {
        // Log to file if database audit fails
        error_log("[AUDIT_FAIL] $action on $tableAffected:$recordId - " . $e->getMessage());
    }
}

/**
 * Get authenticated user ID from session
 */
function getAuthUserId() {
    return $_SESSION['user_id'] ?? $_SESSION['authenticated_user'] ?? 'anonymous';
}

/**
 * Get client IP address, accounting for proxies
 */
function getClientIp() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        // Cloudflare
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Load balancer/proxy
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED'])) {
        return $_SERVER['HTTP_X_FORWARDED'];
    } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_FORWARDED_FOR'];
    } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
        return $_SERVER['HTTP_FORWARDED'];
    } else {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// RATE LIMITING
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Check if request should be rate limited
 * Uses sliding window algorithm with per-endpoint limits
 * @param string $endpoint API endpoint/action name
 * @param int $maxRequests Maximum requests allowed
 * @param int $windowSeconds Time window in seconds
 * @return array ['allowed' => bool, 'remaining' => int, 'retry_after' => int]
 */
function checkRateLimit($endpoint, $maxRequests, $windowSeconds) {
    // Initialize rate limit tracking in session
    if (!isset($_SESSION['rate_limits'])) {
        $_SESSION['rate_limits'] = [];
    }

    $key = $endpoint;
    $now = time();
    $windowStart = $now - $windowSeconds;

    // Initialize or clean old timestamps
    if (!isset($_SESSION['rate_limits'][$key])) {
        $_SESSION['rate_limits'][$key] = [];
    }

    // Remove timestamps outside the window
    $_SESSION['rate_limits'][$key] = array_filter(
        $_SESSION['rate_limits'][$key],
        function($ts) use ($windowStart) { return $ts >= $windowStart; }
    );

    $requestCount = count($_SESSION['rate_limits'][$key]);

    if ($requestCount >= $maxRequests) {
        // Find oldest request to calculate retry_after
        $oldestRequest = min($_SESSION['rate_limits'][$key]);
        $retryAfter = ceil(($oldestRequest + $windowSeconds - $now));

        return [
            'allowed' => false,
            'remaining' => 0,
            'retry_after' => max(1, $retryAfter),
            'error' => 'Rate limit exceeded'
        ];
    }

    // Record this request
    $_SESSION['rate_limits'][$key][] = $now;

    return [
        'allowed' => true,
        'remaining' => $maxRequests - $requestCount - 1,
        'retry_after' => 0
    ];
}

/**
 * Get rate limit configuration for endpoint
 * @param string $action API action
 * @return array ['maxRequests' => int, 'windowSeconds' => int]
 */
function getRateLimitConfig($action) {
    $limits = [
        'login' => ['maxRequests' => 8, 'windowSeconds' => 300],         // 8 per 5 minutes — brute-force guard
        'scan_inbox' => ['maxRequests' => 1, 'windowSeconds' => 300],     // 1 per 5 minutes
        'set_password' => ['maxRequests' => 5, 'windowSeconds' => 900],   // 5 per 15 minutes
        // Raised from 100 to 400 per minute — per-field inline auto-save (e.g. bid
        // sheet row height, inline item edits) resends the full array on every
        // field commit, so heavy interactive editing was hitting 100/min and
        // silently failing saves (looked like the UI was "stuck").
        'save_items' => ['maxRequests' => 400, 'windowSeconds' => 60],
        'save_bidders' => ['maxRequests' => 400, 'windowSeconds' => 60],
        'save_winners' => ['maxRequests' => 400, 'windowSeconds' => 60],
        'save_payments' => ['maxRequests' => 400, 'windowSeconds' => 60],
        'get_all_data' => ['maxRequests' => 10, 'windowSeconds' => 60],   // 10 per minute
        'clear_all' => ['maxRequests' => 1, 'windowSeconds' => 3600],     // 1 per hour
    ];

    return $limits[$action] ?? ['maxRequests' => 100, 'windowSeconds' => 60]; // Default: 100 per minute
}

// ═════════════════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Validate server-side session timeout
 * Checks if session has been idle for too long
 * @param int $timeoutSeconds Default: 1800 (30 minutes)
 * @return array ['valid' => bool, 'message' => string, 'remaining' => int]
 */
function validateSessionTimeout($timeoutSeconds = 1800) {
    $now = time();

    // Initialize last_activity on first request
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = $now;
        return ['valid' => true, 'message' => 'Session started', 'remaining' => $timeoutSeconds];
    }

    $elapsed = $now - $_SESSION['last_activity'];

    if ($elapsed > $timeoutSeconds) {
        // Session has timed out
        session_destroy();
        return [
            'valid' => false,
            'message' => 'Session expired due to inactivity',
            'remaining' => 0
        ];
    }

    // Update last_activity for sliding window
    $_SESSION['last_activity'] = $now;
    $remaining = $timeoutSeconds - $elapsed;

    return [
        'valid' => true,
        'message' => 'Session valid',
        'remaining' => $remaining
    ];
}

// ═════════════════════════════════════════════════════════════════════════════
// DATA VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Validate payment method
 * @param string $method Payment method string
 * @return bool True if method is in whitelist
 */
function isValidPaymentMethod($method) {
    $whitelist = ['Cash', 'Check', 'Credit Card', 'Other'];
    return in_array($method, $whitelist, true);
}

/**
 * Validate payment amount
 * @param mixed $amount Amount to validate
 * @return array ['valid' => bool, 'error' => string]
 */
function validatePaymentAmount($amount) {
    // Convert to float
    $amt = floatval($amount);

    // Must be positive
    if ($amt <= 0) {
        return ['valid' => false, 'error' => 'Amount must be positive'];
    }

    // Check decimal places (max 2)
    if (round($amt, 2) != $amt) {
        return ['valid' => false, 'error' => 'Amount must have at most 2 decimal places'];
    }

    // Reasonable upper limit (adjust as needed)
    if ($amt > 10000) {
        return ['valid' => false, 'error' => 'Amount exceeds maximum limit ($10,000)'];
    }

    return ['valid' => true];
}

/**
 * Validate winning bid amount
 * @param mixed $bid Bid amount
 * @param mixed $itemValue Item value for reference
 * @return array ['valid' => bool, 'error' => string]
 */
function validateWinningBid($bid, $itemValue = null) {
    $bidFloat = floatval($bid);

    // Must be positive
    if ($bidFloat < 0) {
        return ['valid' => false, 'error' => 'Bid amount cannot be negative'];
    }

    // Check decimal places
    if (round($bidFloat, 2) != $bidFloat) {
        return ['valid' => false, 'error' => 'Bid must have at most 2 decimal places'];
    }

    // If itemValue provided, bid should be reasonable
    if ($itemValue !== null) {
        $value = floatval(str_replace('$', '', (string)$itemValue));
        if ($value > 0 && $bidFloat > $value * 5) {
            // Allow up to 5x item value, but log warning
            error_log("[WARNING] Bid $bidFloat is 5x+ item value $value");
        }
    }

    return ['valid' => true];
}

/**
 * Sanitize email input
 * @param string $email Email to sanitize
 * @return string|null Valid email or null
 */
function sanitizeEmail($email) {
    $email = trim((string)$email);
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return $email;
    }
    return null;
}

/**
 * Sanitize phone number (basic)
 * @param string $phone Phone number to sanitize
 * @return string Sanitized phone (numbers and common separators only)
 */
function sanitizePhone($phone) {
    // Keep only digits, dashes, parentheses, spaces, plus sign
    $sanitized = preg_replace('/[^0-9\-\(\)\s\+]/', '', (string)$phone);
    return trim($sanitized);
}

// ═════════════════════════════════════════════════════════════════════════════
// DEBUG LOG MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Log query/event to debug log with rotation
 * @param string $logFile Path to log file
 * @param string $action API action
 * @param string $status Status (SUCCESS, ERROR, etc)
 * @param string $message Log message
 * @param int $maxSize Max log size in bytes (default 10MB)
 */
function logToFile($logFile, $action, $status, $message, $maxSize = 10485760) {
    // Use EDT timezone
    date_default_timezone_set('America/New_York');
    $timestamp = date('m/d/Y, g:i:s A');
    $logEntry = "[$timestamp] [API:$action] [$status] $message\n";

    // Check file size and rotate if needed
    if (file_exists($logFile) && filesize($logFile) > $maxSize) {
        // Rename current log to archive
        $archived = $logFile . '.' . date('Y-m-d-H-i-s') . '.txt';
        rename($logFile, $archived);
    }

    // Write entry
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

/**
 * Clean up old debug logs
 * @param string $logDir Directory containing logs
 * @param int $retentionDays Keep logs for this many days
 */
function cleanupOldLogs($logDir, $retentionDays = 30) {
    if (!is_dir($logDir)) {
        return;
    }

    $files = glob($logDir . '/debug_log.*.txt');
    $cutoffTime = time() - ($retentionDays * 86400);

    foreach ($files as $file) {
        if (filemtime($file) < $cutoffTime) {
            unlink($file);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SOFT DELETE UTILITIES
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Soft delete a record (mark deleted but don't remove)
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param string $idField ID field name
 * @param mixed $idValue ID value
 * @return bool Success
 */
function softDeleteRecord($pdo, $table, $idField, $idValue) {
    try {
        // Ensure table has deleted_at column
        $query = "ALTER TABLE `$table` ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL";
        try {
            $pdo->exec($query);
        } catch (Exception $e) {
            // Column probably already exists
        }

        // Mark as deleted
        $query = "UPDATE `$table` SET deleted_at = NOW() WHERE `$idField` = ?";
        $stmt = $pdo->prepare($query);
        return $stmt->execute([$idValue]);
    } catch (Exception $e) {
        error_log("[SOFT_DELETE_ERROR] " . $e->getMessage());
        return false;
    }
}

/**
 * Restore a soft-deleted record
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param string $idField ID field name
 * @param mixed $idValue ID value
 * @return bool Success
 */
function restoreSoftDeletedRecord($pdo, $table, $idField, $idValue) {
    try {
        $query = "UPDATE `$table` SET deleted_at = NULL WHERE `$idField` = ?";
        $stmt = $pdo->prepare($query);
        return $stmt->execute([$idValue]);
    } catch (Exception $e) {
        error_log("[RESTORE_ERROR] " . $e->getMessage());
        return false;
    }
}

/**
 * Permanently delete records older than retention period
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param int $retentionDays Days to keep soft-deleted records
 * @return int Number of rows deleted
 */
function purgeExpiredSoftDeletes($pdo, $table, $retentionDays = 30) {
    try {
        $cutoffDate = date('Y-m-d H:i:s', time() - ($retentionDays * 86400));
        $query = "DELETE FROM `$table` WHERE deleted_at IS NOT NULL AND deleted_at < ?";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$cutoffDate]);
        return $stmt->rowCount();
    } catch (Exception $e) {
        error_log("[PURGE_ERROR] " . $e->getMessage());
        return 0;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// BACKUP & RECOVERY
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Create a database backup
 * @param PDO $pdo Database connection
 * @param string $backupDir Directory to store backups
 * @param string $dbName Database name
 * @return array ['success' => bool, 'file' => string, 'error' => string]
 */
function createDatabaseBackup($pdo, $backupDir, $dbName) {
    try {
        // Ensure backup directory exists and is writable
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0700, true);
        }

        $backupFile = $backupDir . '/backup_' . date('Y-m-d_H-i-s') . '.sql';
        $gzFile = $backupFile . '.gz';

        // SECURITY: Avoid shell_exec() (command injection risk). Use PHP-based backup instead.
        // This is safer and more portable across hosting environments.
        $tables = ['items', 'bidders', 'winners', 'payments', 'settings', 'audit_log', 'sam_store'];
        $backup = [];
        $backupMeta = [
            'backup_time' => date('Y-m-d H:i:s'),
            'database' => $dbName,
            'version' => '1.0'
        ];

        foreach ($tables as $table) {
            try {
                // Use prepared statement for safety (though table name is hardcoded)
                $rows = $pdo->query("SELECT * FROM `$table`")->fetchAll(PDO::FETCH_ASSOC);
                $backup[$table] = $rows;
            } catch (Exception $e) {
                // Table might not exist, skip
                error_log("[BACKUP] Table $table not found: " . $e->getMessage());
            }
        }

        // Create SQL dump format for readability and restore capability
        $sqlDump = "-- Database Backup\n";
        $sqlDump .= "-- Generated: " . $backupMeta['backup_time'] . "\n";
        $sqlDump .= "-- Database: " . $backupMeta['database'] . "\n\n";
        $sqlDump .= json_encode($backup, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        // Write backup file with restrictive permissions
        if (!file_put_contents($backupFile, $sqlDump, LOCK_EX)) {
            throw new Exception("Failed to write backup file: $backupFile");
        }
        chmod($backupFile, 0600); // Owner read/write only

        // Compress using PHP gzcompress (no shell commands)
        $compressed = gzcompress($sqlDump, 9);
        if ($compressed === false) {
            throw new Exception("Failed to compress backup");
        }

        if (!file_put_contents($gzFile, $compressed, LOCK_EX)) {
            throw new Exception("Failed to write compressed backup: $gzFile");
        }
        chmod($gzFile, 0600); // Owner read/write only

        // Clean up uncompressed file
        @unlink($backupFile);

        if (file_exists($gzFile)) {
            return [
                'success' => true,
                'file' => $gzFile,
                'size' => filesize($gzFile),
                'timestamp' => date('Y-m-d H:i:s')
            ];
        } elseif (file_exists($backupFile)) {
            return [
                'success' => true,
                'file' => $backupFile,
                'size' => filesize($backupFile),
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        return ['success' => false, 'error' => 'Backup file not created'];
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * List available backups
 * @param string $backupDir Backup directory
 * @return array List of backup files with metadata
 */
function listBackups($backupDir) {
    $backups = [];

    if (!is_dir($backupDir)) {
        return $backups;
    }

    $files = glob($backupDir . '/backup_*.sql*');

    foreach ($files as $file) {
        $backups[] = [
            'filename' => basename($file),
            'path' => $file,
            'size' => filesize($file),
            'created' => filemtime($file),
            'created_date' => date('Y-m-d H:i:s', filemtime($file))
        ];
    }

    // Sort by date descending
    usort($backups, function($a, $b) {
        return $b['created'] - $a['created'];
    });

    return $backups;
}

// ═════════════════════════════════════════════════════════════════════════════
// XSS PREVENTION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Escape HTML entities for safe display
 * @param string $text Text to escape
 * @return string Escaped text safe for HTML
 */
function escapeHtml($text) {
    return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
}

/**
 * Check if a string contains HTML/JavaScript
 * @param string $text Text to check
 * @return bool True if potentially dangerous content detected
 */
function containsHtmlOrScript($text) {
    $text = (string)$text;
    $patterns = [
        '/<script/i',
        '/<iframe/i',
        '/javascript:/i',
        '/on\w+\s*=/i',  // Event handlers like onclick=
        '/<embed/i',
        '/<object/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $text)) {
            return true;
        }
    }

    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCTION HARDENING: Enhanced Input Validation & Sanitization
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Sanitize string input: remove control chars, validate encoding, enforce length
 * @param mixed $input Input to sanitize
 * @param int $maxLength Maximum allowed length
 * @return string Sanitized string
 */
function sanitizeInput($input, $maxLength = 10000) {
    if (!is_string($input)) {
        $input = (string)$input;
    }

    // Enforce max length
    if (strlen($input) > $maxLength) {
        error_log("[INPUT_VIOLATION] Input exceeds max length ({$maxLength} chars)");
        return substr($input, 0, $maxLength);
    }

    // Remove null bytes and control characters (except newlines/tabs)
    $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $input);

    // Validate UTF-8 encoding
    if (!mb_check_encoding($input, 'UTF-8')) {
        error_log("[INPUT_ERROR] Invalid UTF-8 encoding detected");
        $input = mb_convert_encoding($input, 'UTF-8', 'UTF-8');
    }

    return trim($input);
}

/**
 * Validate email format
 * @param string $email Email to validate
 * @return bool True if valid email format
 */
function isValidEmail($email) {
    $email = sanitizeInput($email, 254);
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate phone number format (basic check)
 * @param string $phone Phone to validate
 * @return bool True if looks like a phone number
 */
function isValidPhone($phone) {
    $phone = sanitizeInput($phone, 20);
    return preg_match('/^[\d\s\-\(\)\+]+$/', $phone) === 1 && strlen($phone) >= 10;
}

/**
 * Validate numeric ID (positive integer)
 * @param mixed $id ID to validate
 * @return bool True if valid positive integer
 */
function isValidId($id) {
    $id = (int)$id;
    return $id > 0;
}

/**
 * Validate array contains only whitelisted keys
 * @param array $array Array to validate
 * @param array $allowedKeys Whitelist of allowed keys
 * @return array Filtered array with only allowed keys
 */
function filterByWhitelist($array, $allowedKeys) {
    if (!is_array($array)) {
        return [];
    }
    return array_intersect_key($array, array_flip($allowedKeys));
}

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCTION HARDENING: Password & File Security
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Hash a password using bcrypt (OWASP recommendation)
 * @param string $password Password to hash
 * @param int $cost Bcrypt cost (default 12, 10-14 recommended)
 * @return string|null Hashed password or null if hash fails
 */
function hashPassword($password, $cost = 12) {
    if (empty($password) || !is_string($password)) {
        return null;
    }
    $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]);
    return $hashed !== false ? $hashed : null;
}

/**
 * Verify password against bcrypt hash
 * @param string $password Plain text password to verify
 * @param string $hash Bcrypt hash to verify against
 * @return bool True if password matches hash
 */
function verifyPassword($password, $hash) {
    if (empty($password) || empty($hash) || !is_string($password) || !is_string($hash)) {
        return false;
    }
    return password_verify($password, $hash);
}

/**
 * Check if a password needs rehashing (bcrypt cost changed or algorithm upgraded)
 * @param string $hash Current password hash
 * @return bool True if password should be rehashed
 */
function needsRehash($hash) {
    return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Validate file path is within allowed directory (prevent path traversal)
 * @param string $filePath Path to validate
 * @param string $baseDir Base directory that must contain the file
 * @return bool True if file is safely within base directory
 */
function isPathAllowed($filePath, $baseDir) {
    $baseDir = realpath($baseDir);
    $filePath = realpath($filePath);

    if (!$baseDir || !$filePath) {
        return false; // One or both paths don't exist
    }

    // Ensure file is within base directory
    return strpos($filePath, $baseDir . DIRECTORY_SEPARATOR) === 0;
}

/**
 * Safely read file with size limits and encoding validation
 * @param string $filePath File to read
 * @param string $baseDir Base directory for path validation
 * @param int $maxSize Maximum file size to read (default 1MB)
 * @return string|null File contents or null if invalid/too large
 */
function safeReadFile($filePath, $baseDir, $maxSize = 1048576) {
    if (!isPathAllowed($filePath, $baseDir)) {
        error_log("[FILE_ERROR] Path traversal attempt: $filePath");
        return null;
    }

    if (!file_exists($filePath) || !is_readable($filePath)) {
        error_log("[FILE_ERROR] File not readable: $filePath");
        return null;
    }

    $fileSize = filesize($filePath);
    if ($fileSize === false || $fileSize > $maxSize) {
        error_log("[FILE_ERROR] File too large: $filePath ($fileSize bytes)");
        return null;
    }

    $content = file_get_contents($filePath);
    if ($content === false) {
        error_log("[FILE_ERROR] Failed to read file: $filePath");
        return null;
    }

    return $content;
}

/**
 * Safely write file with directory validation
 * @param string $filePath File to write
 * @param string $baseDir Base directory for path validation
 * @param string $content Content to write
 * @param int $permissions File permissions (default 0640 - restrictive)
 * @return bool True if write successful
 */
function safeWriteFile($filePath, $baseDir, $content, $permissions = 0640) {
    if (!isPathAllowed($filePath, $baseDir)) {
        error_log("[FILE_ERROR] Path traversal attempt on write: $filePath");
        return false;
    }

    // Create directory if needed (restrictive permissions)
    $dir = dirname($filePath);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0750, true)) {
            error_log("[FILE_ERROR] Failed to create directory: $dir");
            return false;
        }
    }

    if (file_put_contents($filePath, $content, LOCK_EX) === false) {
        error_log("[FILE_ERROR] Failed to write file: $filePath");
        return false;
    }

    // Set restrictive permissions (owner read/write, group read, no others)
    chmod($filePath, $permissions);
    return true;
}

/**
 * Validate table name is in whitelist (prevent SQL injection via table names)
 * @param string $tableName Table name to validate
 * @param array $whitelist Allowed table names
 * @return bool True if table is whitelisted
 */
function isValidTableName($tableName, $whitelist = []) {
    $defaultWhitelist = [
        'items', 'bidders', 'winners', 'payments', 'settings',
        'audit_log', 'sam_store', 'emails', 'members', 'registrations',
        'auctions', 'workflow_steps'
    ];

    $allowed = !empty($whitelist) ? $whitelist : $defaultWhitelist;
    return in_array($tableName, $allowed, true);
}

/**
 * Escape SQL identifier (table/column names) - use backticks for MySQL
 * @param string $identifier Table or column name to escape
 * @return string Escaped identifier safe for SQL
 */
function escapeSqlIdentifier($identifier) {
    return '`' . str_replace('`', '``', $identifier) . '`';
}

/**
 * Rotate log files older than retention period (prevent disk exhaustion)
 * @param string $logDir Directory containing logs
 * @param int $retentionDays Days to keep logs (default 30)
 * @param int $maxFiles Maximum number of log files to keep
 * @return array Summary of cleanup actions
 */
function rotateLogFiles($logDir, $retentionDays = 30, $maxFiles = 100) {
    $result = ['deleted' => 0, 'errors' => 0];

    if (!is_dir($logDir)) {
        error_log("[LOG_ROTATION] Directory not found: $logDir");
        return $result;
    }

    $cutoffTime = time() - ($retentionDays * 86400);
    $files = glob($logDir . '/*.log', GLOB_NOSORT);

    if (!$files) {
        return $result;
    }

    // Sort by modification time (oldest first)
    usort($files, function($a, $b) {
        return filemtime($a) - filemtime($b);
    });

    // Delete old files
    foreach ($files as $file) {
        if (filemtime($file) < $cutoffTime) {
            if (!unlink($file)) {
                $result['errors']++;
                error_log("[LOG_ROTATION] Failed to delete: $file");
            } else {
                $result['deleted']++;
            }
        }
    }

    // If still too many files, delete oldest until we're under limit
    $remainingFiles = glob($logDir . '/*.log', GLOB_NOSORT);
    if (count($remainingFiles) > $maxFiles) {
        usort($remainingFiles, function($a, $b) {
            return filemtime($a) - filemtime($b);
        });

        $toDelete = count($remainingFiles) - $maxFiles;
        for ($i = 0; $i < $toDelete; $i++) {
            if (!unlink($remainingFiles[$i])) {
                $result['errors']++;
            } else {
                $result['deleted']++;
            }
        }
    }

    return $result;
}

/**
 * Validate database connection and permissions
 * @param PDO $pdo Database connection
 * @return array Status array with 'valid' => bool and any issues found
 */
function validateDatabaseSecurity($pdo) {
    $issues = [];

    try {
        // Check that strict mode is enabled
        $result = $pdo->query("SELECT @@sql_mode")->fetchColumn();
        if (strpos($result, 'STRICT_TRANS_TABLES') === false) {
            $issues[] = 'STRICT_TRANS_TABLES mode not enabled';
        }

        // Check that tables exist
        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        if (empty($tables)) {
            $issues[] = 'No tables found in database';
        }

        // Check for dangerous global variables (should not allow FILE access)
        $filePriv = $pdo->query("SELECT @@secure_file_priv")->fetchColumn();
        if ($filePriv === null || $filePriv === '') {
            $issues[] = 'secure_file_priv not set (FILE operations enabled globally)';
        }

    } catch (Exception $e) {
        $issues[] = 'Database check failed: ' . $e->getMessage();
    }

    return [
        'valid' => empty($issues),
        'issues' => $issues
    ];
}
