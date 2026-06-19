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

$ALLOWED_KEYS = ['sam_items','sam_bidders','sam_winners','sam_payments','sam_settings','sam_fieldmap'];

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 5,
    ]);
} catch (Exception $e) {
    echo json_encode(['error' => 'DB connection failed']);
    exit;
}

// Auto-create table
$pdo->exec("CREATE TABLE IF NOT EXISTS sam_store (
    `key`        VARCHAR(50)  PRIMARY KEY,
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
    if (!in_array($key, $ALLOWED_KEYS, true)) {
        echo json_encode(['error' => 'Invalid key']);
        exit;
    }
    $stmt = $pdo->prepare(
        "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)"
    );
    $stmt->execute([$key, $val]);
    echo json_encode(['ok' => true]);

} else {
    echo json_encode(['error' => 'Unknown action']);
}
