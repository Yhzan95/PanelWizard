<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method not allowed.');
}

if (
    empty($_SESSION['csrf_token']) ||
    !isset($_POST['csrf_token']) ||
    !is_string($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    http_response_code(403);
    exit('Invalid CSRF token.');
}

require_once __DIR__ . '/key/config_crypto.php';
require_once __DIR__ . '/key/auth.php';

$configPath = __DIR__ . '/key/db_config.php';
try {
    $dbConfig = panel_load_db_config($configPath);
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $dbConfig['host'],
        $dbConfig['dbname']
    );
    $conn = new PDO($dsn, $dbConfig['user'], $dbConfig['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    panel_forget_remember_token($conn);
} catch (Throwable $e) {
    error_log('Unable to revoke the remember-me token during logout: ' . $e->getMessage());
    panel_clear_remember_cookie();
}

session_unset();
session_destroy();
header("Location: login.php");
exit();
