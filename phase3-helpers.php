<?php
/**
 * Phase 3 Security Helpers for Silent Auction Manager
 * Implements MEDIUM priority security fixes: rate limiting, validation, pagination, etc.
 */

// ═════════════════════════════════════════════════════════════════════════════
// 1. EMAIL SCAN RATE LIMITING
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Check if email scan is allowed based on cooldown (5 minutes)
 * @param int $minCooldownSeconds Minimum seconds between scans (default 300 = 5 min)
 * @return array { allowed: bool, secondsUntilNext: int, message: string }
 */
function checkEmailScanCooldown($minCooldownSeconds = 300) {
    $lastScanFile = __DIR__ . '/.email_last_scan';
    $now = time();

    // Check if file exists and is recent
    if (file_exists($lastScanFile)) {
        $lastScan = (int)file_get_contents($lastScanFile);
        $elapsed = $now - $lastScan;

        if ($elapsed < $minCooldownSeconds) {
            $remaining = $minCooldownSeconds - $elapsed;
            return [
                'allowed' => false,
                'secondsUntilNext' => $remaining,
                'message' => "Email scan cooldown active. Please wait {$remaining} seconds."
            ];
        }
    }

    // Update last scan time
    file_put_contents($lastScanFile, $now);
    return [
        'allowed' => true,
        'secondsUntilNext' => 0,
        'message' => 'Scan allowed'
    ];
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. PAYMENT VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Validate winning bid amount
 * @param float $winningBid The winning bid amount
 * @param float $itemValue The item's base value
 * @param float $reserveAmount Optional reserve amount
 * @return array { valid: bool, message: string }
 */
// Guarded: validateWinningBid() is also defined in security-helpers.php, which
// loads first. Only declare here if not already present to avoid a fatal redeclare.
if (!function_exists('validateWinningBid')) {
function validateWinningBid($winningBid, $itemValue, $reserveAmount = null) {
    // Ensure values are numeric
    $winningBid = floatval($winningBid);
    $itemValue = floatval($itemValue);
    $reserveAmount = !empty($reserveAmount) ? floatval($reserveAmount) : null;

    // Determine base value for validation
    $baseValue = ($reserveAmount && $reserveAmount > 0) ? $reserveAmount : $itemValue;

    if ($baseValue <= 0) {
        return ['valid' => false, 'message' => 'Invalid item value'];
    }

    // Bid must be at least equal to base value
    if ($winningBid < $baseValue) {
        return ['valid' => false, 'message' => "Winning bid ({$winningBid}) must be at least the item value ({$baseValue})"];
    }

    // Prevent extreme overpayment (bid > 300% of item value)
    $maxBid = $baseValue * 3.0;
    if ($winningBid > $maxBid) {
        return ['valid' => false, 'message' => "Winning bid ({$winningBid}) exceeds maximum (300% of {$baseValue} = {$maxBid})"];
    }

    return ['valid' => true, 'message' => 'Valid bid'];
}
}

/**
 * Validate payment entry
 * @param array $payment Payment record
 * @param string $itemNumber Item number (e.g., '200-3')
 * @param float $winningBid Expected winning bid amount
 * @return array { valid: bool, message: string }
 */
function validatePaymentEntry($payment, $itemNumber, $winningBid) {
    if (!isset($payment['bidder_number'])) {
        return ['valid' => false, 'message' => 'Missing bidder_number'];
    }

    if (!isset($payment['method']) || empty($payment['method'])) {
        return ['valid' => false, 'message' => 'Missing payment method'];
    }

    $validMethods = ['cash', 'check', 'credit_card'];
    if (!in_array($payment['method'], $validMethods, true)) {
        return ['valid' => false, 'message' => "Invalid payment method: {$payment['method']}"];
    }

    // Check for duplicate payment (same item + bidder)
    if (isset($payment['item_number']) && $payment['item_number'] === $itemNumber) {
        if (isset($payment['recorded']) && $payment['recorded'] === true) {
            return ['valid' => false, 'message' => 'Payment already recorded for this item'];
        }
    }

    return ['valid' => true, 'message' => 'Valid payment'];
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. ITEM CATEGORY VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Valid auction item categories
 */
const VALID_ITEM_CATEGORIES = [
    100 => 'General Auto Repair / Car Items',
    200 => 'Corvette Items',
    300 => "Men's Items",
    400 => "Women's Items",
    500 => 'General Household',
    600 => 'Framed Artwork or other Artwork to be Hung',
    700 => 'Baskets / Gift Sets',
    800 => 'Gift Certificates',
    900 => 'Miscellaneous / Other'
];

/**
 * Validate item category code
 * @param int|string $categoryCode The category code
 * @return array { valid: bool, category: string, message: string }
 */
function validateItemCategory($categoryCode) {
    $code = intval($categoryCode);

    if (!isset(VALID_ITEM_CATEGORIES[$code])) {
        return [
            'valid' => false,
            'category' => null,
            'message' => "Invalid category code: {$code}. Valid codes: " . implode(', ', array_keys(VALID_ITEM_CATEGORIES))
        ];
    }

    return [
        'valid' => true,
        'category' => VALID_ITEM_CATEGORIES[$code],
        'message' => 'Valid category'
    ];
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. BIDDER VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Validate email format (RFC 5322 simplified)
 * @param string $email Email address
 * @return bool
 */
function validateEmailFormat($email) {
    $email = trim($email);

    // Simple regex for email validation
    $pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';

    if (!preg_match($pattern, $email)) {
        return false;
    }

    // Additional check: domain has at least one dot
    if (substr_count($email, '@') !== 1) {
        return false;
    }

    return true;
}

/**
 * Validate phone format (10 digits, with optional formatting)
 * @param string $phone Phone number
 * @return bool
 */
function validatePhoneFormat($phone) {
    $phone = preg_replace('/\D/', '', $phone);

    // Must be exactly 10 digits (US format)
    return strlen($phone) === 10 && is_numeric($phone);
}

/**
 * Validate bidder registration data
 * @param array $bidder Bidder object
 * @return array { valid: bool, errors: array }
 */
function validateBidderRegistration($bidder) {
    $errors = [];

    // Check first name
    if (empty($bidder['first_name'])) {
        $errors[] = 'First name is required';
    }

    // Check last name
    if (empty($bidder['last_name'])) {
        $errors[] = 'Last name is required';
    }

    // Check email format
    if (empty($bidder['email'])) {
        $errors[] = 'Email is required';
    } elseif (!validateEmailFormat($bidder['email'])) {
        $errors[] = 'Invalid email format';
    }

    // Check phone format
    if (empty($bidder['phone'])) {
        $errors[] = 'Phone number is required';
    } elseif (!validatePhoneFormat($bidder['phone'])) {
        $errors[] = 'Phone must be 10 digits (US format)';
    }

    return [
        'valid' => count($errors) === 0,
        'errors' => $errors
    ];
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. PAGINATION SUPPORT
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Paginate array results
 * @param array $items Array to paginate
 * @param int $page Current page (1-indexed)
 * @param int $limit Items per page (max 1000)
 * @return array { items: array, page: int, limit: int, total: int, hasMore: bool, totalPages: int }
 */
function paginate($items, $page = 1, $limit = 100) {
    // Enforce reasonable limits
    $limit = min(intval($limit), 1000);
    $limit = max(intval($limit), 1);
    $page = max(intval($page), 1);

    $total = count($items);
    $totalPages = ceil($total / $limit);

    // Ensure page is within bounds
    if ($page > $totalPages && $totalPages > 0) {
        $page = $totalPages;
    }

    $offset = ($page - 1) * $limit;
    $paginated = array_slice($items, $offset, $limit);

    return [
        'items' => $paginated,
        'page' => $page,
        'limit' => $limit,
        'total' => $total,
        'totalPages' => $totalPages,
        'hasMore' => $page < $totalPages,
        'offset' => $offset
    ];
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. REQUEST TIMEOUT HELPER
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Set PHP execution timeout for long-running operations
 * @param int $seconds Timeout in seconds (max 300 for safety)
 */
function setSafeTimeout($seconds = 30) {
    $seconds = min(intval($seconds), 300);
    $seconds = max(intval($seconds), 1);
    set_time_limit($seconds);
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. EXPORT BACKUP SANITIZATION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Sensitive fields that should be excluded from backups
 */
const BACKUP_SENSITIVE_FIELDS = [
    'password',
    'password_hash',
    'auth_token',
    'access_token',
    'refresh_token',
    'csrf_token',
    'session_token',
    'api_key',
    'secret_key',
    'encryption_key',
    'private_key'
];

/**
 * Sanitize data for safe backup export
 * @param array $data Data to sanitize
 * @param array $includeFields Optional whitelist of fields to include
 * @return array Sanitized data
 */
function sanitizeForExport($data, $includeFields = null) {
    if (is_array($data)) {
        $sanitized = [];

        foreach ($data as $key => $value) {
            // Skip sensitive fields
            if (in_array(strtolower($key), BACKUP_SENSITIVE_FIELDS, true)) {
                continue;
            }

            // Apply whitelist if specified
            if ($includeFields !== null && !in_array($key, $includeFields, true)) {
                continue;
            }

            // Recursively sanitize nested arrays
            $sanitized[$key] = is_array($value) ? sanitizeForExport($value, $includeFields) : $value;
        }

        return $sanitized;
    }

    return $data;
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. DUPLICATE EMAIL DETECTION
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Check for duplicate/similar email submissions within time window
 * @param string $description Item description
 * @param string $donorName Donor name
 * @param array $existingEmails Array of existing email records
 * @param int $hoursWindow Time window in hours (default 24)
 * @return array { isDuplicate: bool, similarEmail: ?array, message: string }
 */
function checkDuplicateEmail($description, $donorName, $existingEmails, $hoursWindow = 24) {
    if (!is_array($existingEmails)) {
        return ['isDuplicate' => false, 'similarEmail' => null, 'message' => 'No existing emails'];
    }

    $now = time();
    $windowSeconds = $hoursWindow * 3600;

    // Normalize strings for comparison
    $desc_normalized = strtolower(trim(preg_replace('/\s+/', ' ', $description)));
    $donor_normalized = strtolower(trim(preg_replace('/\s+/', ' ', $donorName)));

    foreach ($existingEmails as $existing) {
        // Check if within time window
        $emailTime = strtotime($existing['date'] ?? 'now');
        if (($now - $emailTime) > $windowSeconds) {
            continue; // Outside window
        }

        $existing_desc = strtolower(trim(preg_replace('/\s+/', ' ', $existing['description'] ?? '')));
        $existing_donor = strtolower(trim(preg_replace('/\s+/', ' ', $existing['donor_name'] ?? '')));

        // Exact match on description AND donor
        if ($desc_normalized === $existing_desc && $donor_normalized === $existing_donor) {
            return [
                'isDuplicate' => true,
                'similarEmail' => $existing,
                'message' => 'Identical item from same donor found in recent emails'
            ];
        }

        // Fuzzy match: description contains existing or vice versa, and donor is same
        if ($donor_normalized === $existing_donor && (
            stripos($desc_normalized, $existing_desc) !== false ||
            stripos($existing_desc, $desc_normalized) !== false
        )) {
            return [
                'isDuplicate' => true,
                'similarEmail' => $existing,
                'message' => 'Similar item from same donor found recently'
            ];
        }
    }

    return ['isDuplicate' => false, 'similarEmail' => null, 'message' => 'No duplicates found'];
}

// ═════════════════════════════════════════════════════════════════════════════
// 9. SECURE SETTINGS MANAGEMENT (Hardcoded values cleanup)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Validate OAuth credentials before storage
 * @param string $clientId OAuth Client ID
 * @param string $clientSecret OAuth Client Secret
 * @return array { valid: bool, message: string }
 */
function validateOAuthCredentials($clientId, $clientSecret = null) {
    // Validate Client ID format (Google format is typically 25+ chars)
    if (empty($clientId) || strlen($clientId) < 20) {
        return ['valid' => false, 'message' => 'Invalid OAuth Client ID format'];
    }

    // Basic pattern check for Google OAuth IDs
    if (!preg_match('/^[\d]+-[a-z0-9]+\.apps\.googleusercontent\.com$/i', $clientId)) {
        return ['valid' => false, 'message' => 'Client ID does not match expected Google OAuth format'];
    }

    return ['valid' => true, 'message' => 'Valid OAuth credentials'];
}

// ═════════════════════════════════════════════════════════════════════════════
// 10. localStorage QUOTA MONITORING (Server-side tracking)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Estimate storage usage for a value
 * @param mixed $value Data to estimate
 * @return int Approximate bytes
 */
function estimateStorageUsage($value) {
    if (is_string($value)) {
        return strlen($value);
    }

    if (is_array($value) || is_object($value)) {
        return strlen(json_encode($value));
    }

    return 0;
}

/**
 * Get estimated storage usage report
 * @param array $storageData Key-value pairs of all stored data
 * @return array { totalBytes: int, estimatedMB: float, percentageUsed: float, warning: bool, message: string }
 */
function getStorageUsageReport($storageData) {
    $totalBytes = 0;

    foreach ($storageData as $key => $value) {
        $totalBytes += strlen($key) + estimateStorageUsage($value);
    }

    // Typical localStorage limit is 5-10MB; assume 5MB
    $quotaBytes = 5 * 1024 * 1024;
    $percentageUsed = ($totalBytes / $quotaBytes) * 100;
    $warningThreshold = 80;

    return [
        'totalBytes' => $totalBytes,
        'estimatedMB' => round($totalBytes / (1024 * 1024), 2),
        'quotaMB' => 5,
        'percentageUsed' => round($percentageUsed, 1),
        'warning' => $percentageUsed >= $warningThreshold,
        'message' => $percentageUsed >= $warningThreshold
            ? "Storage approaching quota: {$percentageUsed}% used"
            : "Storage usage: {$percentageUsed}%"
    ];
}

?>
