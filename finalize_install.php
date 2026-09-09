<?php
declare(strict_types=1);

session_start();
header('Content-Type: application/json; charset=utf-8');

function cleanup_response(bool $success, string $message, int $status = 200): void
{
    http_response_code($status);
    echo json_encode(['success' => $success, 'message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

$remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($remoteAddress, ['127.0.0.1', '::1'], true)) {
    cleanup_response(false, 'Cleanup is only available from this computer.', 403);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    cleanup_response(false, 'Method not allowed.', 405);
}

$providedToken = $_POST['cleanup_token'] ?? '';
$expectedToken = $_SESSION['cleanup_token'] ?? '';
if (
    empty($_SESSION['installation_complete']) ||
    !is_string($providedToken) ||
    !is_string($expectedToken) ||
    $expectedToken === '' ||
    !hash_equals($expectedToken, $providedToken)
) {
    cleanup_response(false, 'Invalid cleanup token.', 403);
}

$applicationDirectory = realpath(__DIR__);
$installDirectory = realpath(__DIR__ . '/install');
if (
    $applicationDirectory === false ||
    $installDirectory === false ||
    dirname($installDirectory) !== $applicationDirectory ||
    basename($installDirectory) !== 'install'
) {
    cleanup_response(false, 'Refusing to remove an unexpected directory.', 500);
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($installDirectory, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST
);

$errors = [];
foreach ($iterator as $item) {
    $path = $item->getPathname();
    $removed = $item->isDir() && !$item->isLink() ? @rmdir($path) : @unlink($path);
    if (!$removed) {
        $errors[] = $path;
    }
}

if (!$errors && !@rmdir($installDirectory)) {
    $errors[] = $installDirectory;
}

if ($errors) {
    error_log('Unable to remove installer paths: ' . implode(', ', $errors));
    cleanup_response(false, 'Some installer files could not be removed. Delete /install manually.', 500);
}

unset(
    $_SESSION['installation_complete'],
    $_SESSION['installation_in_progress'],
    $_SESSION['cleanup_token'],
    $_SESSION['install_csrf_token']
);

cleanup_response(true, 'Installer removed.');
