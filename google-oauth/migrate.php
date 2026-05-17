<?php
/**
 * Google OAuth migration — adds google_id column to the users table.
 * Run this once, either via CLI or by visiting the URL while logged in as admin.
 * It is safe to run multiple times (idempotent).
 */

require_once '../../config/app.php';
require_once '../../config/database.php';
initializeApp();

// Restrict to admins when accessed via browser
if (php_sapi_name() !== 'cli') {
    if (empty($_SESSION['is_admin'])) {
        http_response_code(403);
        exit('Forbidden — admin access required.');
    }
}

try {
    $pdo = getDbConnection();

    // Check whether the column already exists
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME   = 'users'
           AND COLUMN_NAME  = 'google_id'"
    );
    $stmt->execute();
    $exists = (bool)$stmt->fetchColumn();

    if ($exists) {
        echo "Column google_id already exists — nothing to do.\n";
    } else {
        $pdo->exec(
            "ALTER TABLE users
             ADD COLUMN google_id VARCHAR(100) NULL DEFAULT NULL AFTER email,
             ADD INDEX idx_google_id (google_id)"
        );
        echo "Migration complete: google_id column added to users table.\n";
    }
} catch (\Exception $e) {
    http_response_code(500);
    echo "Migration failed: " . $e->getMessage() . "\n";
}
