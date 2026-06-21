<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { exit; }

$host = 'localhost';
$db   = 'u177039107_sam';
$user = 'u177039107_sam';
$pass = 'uemk$td*TjnAD9t4HXeYdsBQfqDDSZ4m';

// Allowed key suffixes (after sam_ prefix). Supports both static keys (sam_items)
// and namespaced keys (sam_{auctionId}_items)
$ALLOWED_SUFFIXES = ['items', 'bidders', 'winners', 'payments', 'settings', 'fieldmap', 'emails', 'members', 'regdb', 'auctions', 'current_auction'];

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 5,
    ]);
} catch (Exception $e) {
    echo json_encode(['error' => 'DB connection failed']);
    exit;
}

// Auto-create table (increase VARCHAR size to handle longer namespaced keys)
$pdo->exec("CREATE TABLE IF NOT EXISTS sam_store (
    `key`        VARCHAR(100) PRIMARY KEY,
    `value`      LONGTEXT     NOT NULL,
    `updated_at` TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$input  = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $input['action'] ?? '';

if ($action === 'get_all') {
    $rows = $pdo->query("SELECT `key`, `value` FROM sam_store")->fetchAll(PDO::FETCH_KEY_PAIR);
    echo json_encode((object)$rows);

} elseif ($action === 'set') {
    $key = $input['key']   ?? '';
    $val = $input['value'] ?? '';

    // Check if key is allowed. Supports static keys (sam_items) and
    // namespaced keys (sam_{auctionId}_items, sam_{auctionId}_{suffix})
    $isAllowed = false;
    if (strpos($key, 'sam_') === 0) {
        // Extract the part after 'sam_'
        $rest = substr($key, 4);
        // Find the last underscore to extract the suffix
        $lastUnderscore = strrpos($rest, '_');
        if ($lastUnderscore === false) {
            // No underscore: static key like 'sam_members', check exact match
            $isAllowed = in_array($rest, $ALLOWED_SUFFIXES, true);
        } else {
            // Has underscore: namespaced key like 'sam_{id}_items'
            // Extract suffix after last underscore
            $suffix = substr($rest, $lastUnderscore + 1);
            $isAllowed = in_array($suffix, $ALLOWED_SUFFIXES, true);
        }
    }
    if (!$isAllowed) {
        echo json_encode(['error' => 'Invalid key']);
        exit;
    }
    $stmt = $pdo->prepare(
        "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)"
    );
    $stmt->execute([$key, $val]);
    echo json_encode(['ok' => true]);

} elseif ($action === 'clear_all') {
    // Purge all stored data. Requires a token to prevent accidental clearing.
    $token = $input['token'] ?? '';
    if ($token !== 'samclear2026') {
        echo json_encode(['error' => 'Invalid or missing token']);
        exit;
    }
    $pdo->exec("TRUNCATE TABLE sam_store");
    echo json_encode(['ok' => true, 'message' => 'All data cleared']);

} elseif ($action === 'log') {
    $message = $input['message'] ?? '';
    $level = $input['level'] ?? 'INFO';
    if (!$message) {
        echo json_encode(['error' => 'No message provided']);
        exit;
    }
    // Append to debug_log.txt
    $logFile = __DIR__ . '/debug_log.txt';
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    echo json_encode(['ok' => true, 'message' => 'Logged']);

} else {
    echo json_encode(['error' => 'Unknown action']);
}
