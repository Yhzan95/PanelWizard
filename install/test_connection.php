<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

function json_response(bool $success, string $message): void {
    echo json_encode([
        'success' => $success,
        'message' => $message
    ], JSON_UNESCAPED_UNICODE);

    exit;
}

$remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';
if (PHP_SAPI !== 'cli' && !in_array($remoteAddress, ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    json_response(false, 'The installer is only available from this computer.');
}

if (
    empty($_SESSION['install_csrf_token']) ||
    !isset($_POST['csrf_token']) ||
    !is_string($_POST['csrf_token']) ||
    !hash_equals($_SESSION['install_csrf_token'], $_POST['csrf_token'])
) {
    http_response_code(403);
    json_response(false, 'Invalid CSRF token.');
}

$host = isset($_POST['host']) ? trim($_POST['host']) : '';
$user = isset($_POST['user']) ? trim($_POST['user']) : '';
$password = isset($_POST['password']) ? (string) $_POST['password'] : '';
$dbname = isset($_POST['dbname']) ? trim($_POST['dbname']) : '';

if ($host === '' || $user === '' || $dbname === '') {
    json_response(
        false,
        'Host, username and database name are required.'
    );
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $dbname)) {
    json_response(
        false,
        'Invalid database name. Use only letters, numbers and underscores.'
    );
}

try {
    $pdo = new PDO(
        'mysql:host=' . $host . ';charset=utf8mb4',
        $user,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );

    $pdo->query('SELECT 1');

    json_response(
        true,
        'Connection successful. The database will be created after you click Next.'
    );
} catch (PDOException $e) {
    error_log('MySQL installation test failed: ' . $e->getMessage());
    json_response(
        false,
        'Unable to connect to MySQL with these credentials.'
    );
} catch (Throwable $e) {
    error_log('Installation test failed: ' . $e->getMessage());
    json_response(
        false,
        'Unable to complete the connection test. Check the server logs.'
    );
}
