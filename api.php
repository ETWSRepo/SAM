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

// Logging helper
function logQuery($action, $query, $status, $details = '') {
    $logFile = __DIR__ . '/debug_log.txt';
    // Use EDT timezone for consistency with UI
    date_default_timezone_set('America/New_York');
    $timestamp = date('m/d/Y, g:i:s A');
    $logEntry = "[$timestamp] [API:$action] [$status] $query";
    if ($details) $logEntry .= " | $details";
    $logEntry .= "\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

$input  = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $input['action'] ?? '';
logQuery($action, 'START', 'REQUEST', "Action=$action");

if ($action === 'get_all') {
    try {
        $query = "SELECT `key`, `value` FROM sam_store";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_KEY_PAIR);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode((object)$rows);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to get data']);
    }

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

} elseif ($action === 'get_auctions') {
    // Read auctions from MySQL table
    try {
        $rows = $pdo->query("SELECT * FROM auctions")->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($rows);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Failed to read auctions: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_all_data') {
    // Read all data from MySQL tables
    try {
        $data = [
            'auctions' => $pdo->query("SELECT * FROM auctions")->fetchAll(PDO::FETCH_ASSOC),
            'items' => $pdo->query("SELECT * FROM items")->fetchAll(PDO::FETCH_ASSOC),
            'bidders' => $pdo->query("SELECT * FROM bidders")->fetchAll(PDO::FETCH_ASSOC),
            'winners' => $pdo->query("SELECT * FROM winners")->fetchAll(PDO::FETCH_ASSOC),
            'payments' => $pdo->query("SELECT * FROM payments")->fetchAll(PDO::FETCH_ASSOC),
            'settings' => $pdo->query("SELECT * FROM settings")->fetchAll(PDO::FETCH_ASSOC),
        ];
        echo json_encode($data);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Failed to read data: ' . $e->getMessage()]);
    }

} elseif ($action === 'db_stats') {
    // Get database statistics from all SQL tables
    try {
        $query = "SHOW TABLES";
        $tables = $pdo->query($query)->fetchAll(PDO::FETCH_COLUMN);
        $stats = [];
        $totalRows = 0;

        foreach ($tables as $table) {
            $countQuery = "SELECT COUNT(*) FROM `$table`";
            $count = $pdo->query($countQuery)->fetchColumn();
            $stats[$table] = (int)$count;
            $totalRows += $count;
        }

        logQuery($action, 'Database statistics', 'SUCCESS', 'Total rows: ' . $totalRows);
        echo json_encode([
            'stats' => $stats,
            'total_rows' => $totalRows,
            'table_count' => count($stats)
        ]);
    } catch (Exception $e) {
        logQuery($action, 'Database statistics', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to get database stats: ' . $e->getMessage()]);
    }

} elseif ($action === 'show_tables') {
    // Show all tables and their row counts
    try {
        $query = "SHOW TABLES";
        $tables = $pdo->query($query)->fetchAll(PDO::FETCH_COLUMN);
        $result = [];
        foreach ($tables as $table) {
            $countQuery = "SELECT COUNT(*) FROM `$table`";
            $count = $pdo->query($countQuery)->fetchColumn();
            $descQuery = "DESCRIBE `$table`";
            $columns = $pdo->query($descQuery)->fetchAll(PDO::FETCH_ASSOC);
            $result[] = [
                'table' => $table,
                'rows' => $count,
                'columns' => count($columns),
                'fields' => array_map(function($col) { return $col['Field']; }, $columns)
            ];
        }
        logQuery($action, $query, 'SUCCESS', 'Tables: ' . count($result));
        echo json_encode($result);
    } catch (Exception $e) {
        logQuery($action, 'SHOW TABLES', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to show tables: ' . $e->getMessage()]);
    }

} elseif ($action === 'show_keys') {
    // Show all keys in sam_store
    try {
        $query = "SELECT `key` FROM sam_store ORDER BY `key`";
        $keys = $pdo->query($query)->fetchAll(PDO::FETCH_COLUMN);
        logQuery($action, $query, 'SUCCESS', 'Keys: ' . count($keys));
        echo json_encode(['keys' => $keys, 'total' => count($keys)]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to show keys: ' . $e->getMessage()]);
    }

} elseif ($action === 'init_tables') {
    // Initialize application tables
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS auctions (
            id VARCHAR(50) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'active',
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS items (
            item_number VARCHAR(20) PRIMARY KEY,
            email_message_id VARCHAR(255),
            item_category VARCHAR(255),
            description LONGTEXT,
            item_value VARCHAR(20),
            reserve_amount VARCHAR(20),
            donor_name VARCHAR(255),
            donor_email VARCHAR(255),
            donor_phone VARCHAR(20),
            submission_date VARCHAR(255),
            date_loaded TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_category (item_category)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS bidders (
            bidder_number INT PRIMARY KEY,
            last_name VARCHAR(255),
            first_name VARCHAR(255),
            email VARCHAR(255),
            phone VARCHAR(20),
            bidder_type VARCHAR(50),
            INDEX idx_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Drop old winners table to recreate with corrected schema
        $pdo->exec("DROP TABLE IF EXISTS winners");

        $pdo->exec("CREATE TABLE IF NOT EXISTS winners (
            id INT AUTO_INCREMENT PRIMARY KEY,
            item_number VARCHAR(20),
            bidder_number INT NULL,
            bidder_name VARCHAR(255),
            winning_bid VARCHAR(20),
            UNIQUE KEY unique_item (item_number),
            FOREIGN KEY (item_number) REFERENCES items(item_number)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Drop old payments table to recreate with corrected schema
        $pdo->exec("DROP TABLE IF EXISTS payments");

        $pdo->exec("CREATE TABLE IF NOT EXISTS payments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            bidder_number INT NULL,
            checknum VARCHAR(50),
            method VARCHAR(50),
            paid INT,
            other VARCHAR(255),
            otherReason VARCHAR(255),
            UNIQUE KEY unique_bidder (bidder_number)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            gmailClientId VARCHAR(255),
            inboxEmail VARCHAR(255),
            debugMode INT,
            environment VARCHAR(50),
            versionMajor INT,
            versionMinor INT,
            startingBidPct INT,
            finalBidPct INT,
            bidCount INT,
            squarePct DECIMAL(5,2),
            squareFee DECIMAL(5,2),
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS emails (
            id VARCHAR(255) PRIMARY KEY,
            auction_id VARCHAR(50),
            from_email VARCHAR(255),
            subject VARCHAR(255),
            body LONGTEXT,
            received TIMESTAMP,
            FOREIGN KEY (auction_id) REFERENCES auctions(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS members (
            member_number INT PRIMARY KEY,
            last_name VARCHAR(255),
            first_name VARCHAR(255),
            primary_email VARCHAR(255),
            cell_phone VARCHAR(20),
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (primary_email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS registrations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            member_number INT,
            last_name VARCHAR(255),
            first_name VARCHAR(255),
            email VARCHAR(255),
            cell_phone VARCHAR(20),
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_member (member_number),
            INDEX idx_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        echo json_encode(['success' => true, 'message' => 'Database tables initialized successfully']);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Failed to initialize tables: ' . $e->getMessage()]);
    }

// ═══════════════════════════════════════════════════════════════════════════
// TABLE CRUD OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

} elseif ($action === 'get_auctions') {
    try {
        $query = "SELECT id, name, status, created FROM auctions ORDER BY created DESC";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM auctions', 'ERROR', $e->getMessage());
        // Fallback to key-value store
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_auctions' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'delete_auction') {
    $auctionId = $input['id'] ?? '';
    if (!$auctionId) {
        echo json_encode(['error' => 'No auction ID provided']);
        exit;
    }
    try {
        $query = "DELETE FROM auctions WHERE id = ?";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$auctionId]);
        logQuery($action, $query, 'SUCCESS', "Deleted auction: $auctionId");
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to delete auction: ' . $e->getMessage()]);
    }

} elseif ($action === 'save_auctions') {
    $data = $input['data'] ?? [];
    try {
        // Upsert auctions into SQL table (insert or update if exists)
        $insertQuery = "INSERT INTO auctions (id, name, status, created, updated) VALUES (?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE name = VALUES(name), status = VALUES(status), updated = NOW()";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $auction) {
            $stmt->execute([
                $auction['id'] ?? null,
                $auction['name'] ?? null,
                $auction['status'] ?? 'active',
                $auction['created'] ?? date('c')
            ]);
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_auctions', json_encode($data)]);

        $count = count($data);
        logQuery($action, $insertQuery, 'SUCCESS', "Saved $count auctions to SQL table");
        echo json_encode(['ok' => true, 'count' => $count]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save auctions: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_items') {
    try {
        $query = "SELECT * FROM items";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM items', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_items' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'save_items') {
    $data = $input['data'] ?? [];
    $count = 0;
    $totalItems = count($data);

    // Log detailed info about what's being received
    error_log("[save_items] Received $totalItems items");
    if ($totalItems === 0) {
        error_log("[save_items] WARNING: Empty items array!");
    } else if ($totalItems > 0 && isset($data[0])) {
        error_log("[save_items] First item: " . json_encode($data[0]));
    }

    logQuery($action, 'START', 'INFO', "Received $totalItems items to save");

    try {
        // Upsert items (insert or update if exists)
        // Map fields to correct database column names
        $insertQuery = "INSERT INTO items (item_number, item_category, email_message_id, description, item_value, reserve_amount, donor_name, donor_email, donor_phone, submission_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE item_category=VALUES(item_category), description=VALUES(description), item_value=VALUES(item_value), reserve_amount=VALUES(reserve_amount), donor_name=VALUES(donor_name), donor_email=VALUES(donor_email), donor_phone=VALUES(donor_phone)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $idx => $item) {
            try {
                $itemNum = $item['item_number'] ?? null;
                $desc = $item['description'] ?? null;

                if (!$itemNum) {
                    logQuery($action, $insertQuery, 'ERROR', "Item #$idx has no item_number. Data: " . json_encode($item));
                    continue;
                }

                // Map item fields to correct database columns
                $category = $item['category_name'] ?? $item['item_category'] ?? $item['category_code'] ?? null;
                $value = $item['item_value'] ?? $item['value'] ?? null;
                $submissionDate = $item['submission_date'] ?? $item['loaded_date'] ?? date('Y-m-d H:i:s');

                $execData = [
                    $itemNum,
                    $category,
                    $item['email_message_id'] ?? null,
                    $desc,
                    $value,
                    $item['reserve_amount'] ?? null,
                    $item['donor_name'] ?? null,
                    $item['donor_email'] ?? null,
                    $item['donor_phone'] ?? null,
                    $submissionDate
                ];

                $stmt->execute($execData);
                $count++;
            } catch (Exception $itemErr) {
                logQuery($action, $insertQuery, 'ERROR', "Failed to insert item {$item['item_number']}: " . $itemErr->getMessage());
            }
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_items', json_encode($data)]);

        logQuery($action, $insertQuery, 'SUCCESS', "Saved/updated $count of $totalItems items to SQL table");
        echo json_encode(['ok' => true, 'count' => $count, 'total' => $totalItems]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save items: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_bidders') {
    try {
        $query = "SELECT * FROM bidders ORDER BY bidder_number";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM bidders', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_bidders' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'save_bidders') {
    $data = $input['data'] ?? [];
    $count = 0;
    try {
        // Upsert bidders (insert or update if exists)
        $insertQuery = "INSERT INTO bidders (bidder_number, last_name, first_name, email, phone) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE last_name=VALUES(last_name), first_name=VALUES(first_name), email=VALUES(email), phone=VALUES(phone)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $bidder) {
            try {
                $stmt->execute([
                    $bidder['bidder_number'] ?? null,
                    $bidder['last_name'] ?? null,
                    $bidder['first_name'] ?? null,
                    $bidder['email'] ?? null,
                    $bidder['phone'] ?? null
                ]);
                $count++;
            } catch (Exception $bidErr) {
                logQuery($action, $insertQuery, 'ERROR', "Failed to insert bidder {$bidder['bidder_number']}: " . $bidErr->getMessage());
            }
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_bidders', json_encode($data)]);

        logQuery($action, $insertQuery, 'SUCCESS', "Saved/updated $count bidders to SQL table");
        echo json_encode(['ok' => true, 'count' => $count]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save bidders: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_winners') {
    try {
        $query = "SELECT * FROM winners";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        $result = [];
        foreach ($rows as $row) {
            $result[$row['item_number']] = $row;
        }
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($result);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM winners', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_winners' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '{}';
    }

} elseif ($action === 'save_winners') {
    $data = $input['data'] ?? [];
    $count = 0;

    // Log detailed info about what's being received
    error_log("[save_winners] Received " . count($data) . " winners");
    if (count($data) > 0) {
        $firstItem = array_key_first($data);
        if ($firstItem) {
            error_log("[save_winners] First item ($firstItem): " . json_encode($data[$firstItem]));
        }
    }

    try {
        // Upsert winners (insert or update if exists)
        $insertQuery = "INSERT INTO winners (item_number, bidder_number, bidder_name, winning_bid) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE bidder_number=VALUES(bidder_number), bidder_name=VALUES(bidder_name), winning_bid=VALUES(winning_bid)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $itemNum => $winner) {
            try {
                $bidNum = $winner['bidder_number'] ?? null;
                $bidName = $winner['bidder_name'] ?? null;
                $bid = $winner['winning_bid'] ?? null;

                error_log("[save_winners] Inserting: item=$itemNum, bidder_number=$bidNum, bidder_name=$bidName, winning_bid=$bid");

                $stmt->execute([
                    $itemNum,
                    $bidNum,
                    $bidName,
                    $bid
                ]);
                $count++;
            } catch (Exception $winErr) {
                logQuery($action, $insertQuery, 'ERROR', "Failed to insert winner for item $itemNum: " . $winErr->getMessage());
            }
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_winners', json_encode($data)]);

        logQuery($action, $insertQuery, 'SUCCESS', "Saved/updated $count winners to SQL table");
        echo json_encode(['ok' => true, 'count' => $count]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save winners: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_payments') {
    try {
        $query = "SELECT * FROM payments";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        $result = [];
        foreach ($rows as $row) {
            $result[$row['bidder_number']] = $row;
        }
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($result);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM payments', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_payments' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '{}';
    }

} elseif ($action === 'save_payments') {
    $data = $input['data'] ?? [];
    $count = 0;

    // Log detailed info about what's being received
    error_log("[save_payments] Received " . count($data) . " payments");
    if (count($data) > 0) {
        $firstKey = array_key_first($data);
        if ($firstKey !== null) {
            error_log("[save_payments] First payment (bidder $firstKey): " . json_encode($data[$firstKey]));
        }
    }

    logQuery($action, 'START', 'INFO', "Received " . count($data) . " payments to save");

    try {
        // Upsert payments (insert or update if exists)
        $insertQuery = "INSERT INTO payments (bidder_number, checknum, method, paid, other, otherReason) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE checknum=VALUES(checknum), method=VALUES(method), paid=VALUES(paid), other=VALUES(other), otherReason=VALUES(otherReason)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $bidderNum => $payment) {
            try {
                $checknum = $payment['checknum'] ?? null;
                $method = $payment['method'] ?? null;
                $paid = $payment['paid'] ?? null;
                $other = $payment['other'] ?? null;
                $otherReason = $payment['otherReason'] ?? null;

                error_log("[save_payments] Inserting: bidder=$bidderNum, checknum=$checknum, method=$method, paid=$paid");

                $stmt->execute([
                    $bidderNum,
                    $checknum,
                    $method,
                    $paid,
                    $other,
                    $otherReason
                ]);
                $count++;
            } catch (Exception $payErr) {
                logQuery($action, $insertQuery, 'ERROR', "Failed to insert payment for bidder $bidderNum: " . $payErr->getMessage());
            }
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_payments', json_encode($data)]);

        logQuery($action, $insertQuery, 'SUCCESS', "Saved/updated $count payments to SQL table");
        echo json_encode(['ok' => true, 'count' => $count]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save payments: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_settings') {
    try {
        $query = "SELECT * FROM settings LIMIT 1";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        if ($rows) {
            echo json_encode($rows[0]);
        } else {
            // Fallback
            $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_settings' LIMIT 1";
            $val = $pdo->query($query)->fetchColumn();
            logQuery($action, $query, 'FALLBACK', 'Using key-value store');
            echo $val ?: '{}';
        }
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM settings', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_settings' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '{}';
    }

} elseif ($action === 'save_settings') {
    $data = $input['data'] ?? [];
    try {
        $query = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $stmt = $pdo->prepare($query);
        $stmt->execute(['sam_settings', json_encode($data)]);
        logQuery($action, $query, 'SUCCESS', 'Saved settings');
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save settings: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_members') {
    try {
        $query = "SELECT member_number, last_name, first_name, primary_email, cell_phone FROM members ORDER BY member_number";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM members', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_members' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'save_members') {
    $data = $input['data'] ?? [];
    try {
        // Clear existing members
        $pdo->exec("DELETE FROM members");

        // Insert new members into SQL table
        $insertQuery = "INSERT INTO members (member_number, last_name, first_name, primary_email, cell_phone) VALUES (?, ?, ?, ?, ?)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $member) {
            $stmt->execute([
                $member['member_number'] ?? null,
                $member['last_name'] ?? null,
                $member['first_name'] ?? null,
                $member['primary_email'] ?? null,
                $member['cell_phone'] ?? null
            ]);
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_members', json_encode($data)]);

        $count = count($data);
        $timestamp = date('Y-m-d H:i:s');
        logQuery($action, $insertQuery, 'SUCCESS', "Inserted $count members into SQL table at $timestamp");
        echo json_encode(['ok' => true, 'count' => $count, 'imported_at' => $timestamp]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save members: ' . $e->getMessage()]);
    }

} elseif ($action === 'save_workflow_step') {
    $auctionId = $input['auction_id'] ?? '';
    $stepName = $input['step_name'] ?? '';
    $timestamp = $input['timestamp'] ?? null;

    if (!$auctionId || !$stepName) {
        echo json_encode(['error' => 'Missing auction_id or step_name']);
        exit;
    }

    try {
        $key = "sam_${auctionId}_ts_${stepName}";
        $query = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$key, (string)$timestamp]);
        logQuery($action, $query, 'SUCCESS', "Saved workflow step: $stepName for auction: $auctionId");
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save workflow step: ' . $e->getMessage()]);
    }

} elseif ($action === 'delete_workflow_step') {
    $auctionId = $input['auction_id'] ?? '';
    $stepName = $input['step_name'] ?? '';

    if (!$auctionId || !$stepName) {
        echo json_encode(['error' => 'Missing auction_id or step_name']);
        exit;
    }

    try {
        $key = "sam_${auctionId}_ts_${stepName}";
        $query = "DELETE FROM sam_store WHERE `key` = ?";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$key]);
        logQuery($action, $query, 'SUCCESS', "Deleted workflow step: $stepName for auction: $auctionId");
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to delete workflow step: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_regdb') {
    try {
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_regdb' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'SUCCESS', 'Registration database retrieved');
        echo $val ?: '[]';
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to get registration database: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_registrations') {
    try {
        $query = "SELECT member_number, last_name, first_name, email, cell_phone FROM registrations ORDER BY member_number";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM registrations', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_regdb' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'save_registrations') {
    $data = $input['data'] ?? [];
    try {
        // Clear existing registrations
        $pdo->exec("DELETE FROM registrations");

        // Insert new registrations into SQL table
        $insertQuery = "INSERT INTO registrations (member_number, last_name, first_name, email, cell_phone) VALUES (?, ?, ?, ?, ?)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $reg) {
            $stmt->execute([
                $reg['member_number'] ?? null,
                $reg['last_name'] ?? null,
                $reg['first_name'] ?? null,
                $reg['email'] ?? null,
                $reg['cell_phone'] ?? null
            ]);
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_regdb', json_encode($data)]);

        $count = count($data);
        $timestamp = date('Y-m-d H:i:s');
        logQuery($action, $insertQuery, 'SUCCESS', "Inserted $count registrations into SQL table at $timestamp");
        echo json_encode(['ok' => true, 'count' => $count, 'registered_at' => $timestamp]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save registrations: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_fieldmap') {
    try {
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_fieldmap' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'SUCCESS', 'Field map retrieved');
        echo $val ?: 'null';
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to get field map: ' . $e->getMessage()]);
    }

} elseif ($action === 'save_fieldmap') {
    $data = $input['data'] ?? [];
    try {
        $query = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $stmt = $pdo->prepare($query);
        $stmt->execute(['sam_fieldmap', json_encode($data)]);
        logQuery($action, $query, 'SUCCESS', 'Field map saved');
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        logQuery($action, $query ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save field map: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_emails') {
    try {
        $query = "SELECT * FROM emails ORDER BY received DESC LIMIT 1000";
        $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
        logQuery($action, $query, 'SUCCESS', 'Rows: ' . count($rows));
        echo json_encode($rows);
    } catch (Exception $e) {
        logQuery($action, 'SELECT * FROM emails', 'ERROR', $e->getMessage());
        // Fallback
        $query = "SELECT `value` FROM sam_store WHERE `key` = 'sam_emails' LIMIT 1";
        $val = $pdo->query($query)->fetchColumn();
        logQuery($action, $query, 'FALLBACK', 'Using key-value store');
        echo $val ?: '[]';
    }

} elseif ($action === 'save_emails') {
    $data = $input['data'] ?? [];
    try {
        // Clear existing emails
        $pdo->exec("DELETE FROM emails");

        // Insert new emails into SQL table
        $insertQuery = "INSERT INTO emails (id, auction_id, from_email, subject, body, received) VALUES (?, ?, ?, ?, ?, ?)";
        $stmt = $pdo->prepare($insertQuery);

        foreach ($data as $email) {
            $stmt->execute([
                $email['id'] ?? $email['message_id'] ?? null,
                $email['auction_id'] ?? null,
                $email['from'] ?? null,
                $email['subject'] ?? null,
                $email['body'] ?? null,
                $email['received'] ?? date('c')
            ]);
        }

        // Also save to key-value store as backup
        $kvQuery = "INSERT INTO sam_store (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        $kvStmt = $pdo->prepare($kvQuery);
        $kvStmt->execute(['sam_emails', json_encode($data)]);

        $count = count($data);
        logQuery($action, $insertQuery, 'SUCCESS', "Inserted $count emails into SQL table");
        echo json_encode(['ok' => true, 'count' => $count]);
    } catch (Exception $e) {
        logQuery($action, $insertQuery ?? 'N/A', 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to save emails: ' . $e->getMessage()]);
    }

} elseif ($action === 'get_table_data') {
    $table = $input['table'] ?? '';
    // Whitelist allowed tables
    $allowedTables = ['sam_store', 'auctions', 'items', 'bidders', 'winners', 'payments', 'settings', 'emails', 'members', 'registrations'];

    if (!in_array($table, $allowedTables)) {
        logQuery($action, 'N/A', 'ERROR', "Invalid table: $table");
        echo json_encode(['error' => 'Invalid table']);
        exit;
    }

    try {
        if ($table === 'sam_store') {
            // Special handling for key-value store
            $query = "SELECT `key`, LEFT(`value`, 200) as `value_preview`, LENGTH(`value`) as `value_length`, `updated_at` FROM sam_store ORDER BY `key`";
            $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
            logQuery($action, $query, 'SUCCESS', "Rows: " . count($rows));
            echo json_encode([
                'table' => $table,
                'columns' => ['key', 'value_preview', 'value_length', 'updated_at'],
                'rows' => $rows,
                'count' => count($rows)
            ]);
        } else {
            // Regular table
            $query = "SELECT * FROM `$table` LIMIT 1000";
            $rows = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
            $columns = $rows ? array_keys($rows[0]) : [];
            logQuery($action, "SELECT * FROM `$table` LIMIT 1000", 'SUCCESS', "Rows: " . count($rows));
            echo json_encode([
                'table' => $table,
                'columns' => $columns,
                'rows' => $rows,
                'count' => count($rows)
            ]);
        }
    } catch (Exception $e) {
        logQuery($action, "SELECT * FROM `$table`", 'ERROR', $e->getMessage());
        echo json_encode(['error' => 'Failed to fetch table: ' . $e->getMessage()]);
    }

} elseif ($action === 'log') {
    $message = $input['message'] ?? '';
    $level = $input['level'] ?? 'INFO';
    if (!$message) {
        echo json_encode(['error' => 'No message provided']);
        exit;
    }
    // Append to debug_log.txt with EDT timezone
    $logFile = __DIR__ . '/debug_log.txt';
    date_default_timezone_set('America/New_York');
    $timestamp = date('m/d/Y, g:i:s A');
    $logEntry = "[$timestamp] [$level] $message\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    echo json_encode(['ok' => true, 'message' => 'Logged']);

} else {
    echo json_encode(['error' => 'Unknown action']);
}
