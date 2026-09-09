<?php
declare(strict_types=1);

const PANEL_REMEMBER_COOKIE = 'panel_remember';
const PANEL_REMEMBER_DAYS = 30;

function panel_ensure_auth_schema(PDO $pdo): void
{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS remember_tokens (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            selector CHAR(24) NOT NULL UNIQUE,
            validator_hash CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_remember_user (user_id),
            INDEX idx_remember_expiry (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    $pdo->exec('DELETE FROM remember_tokens WHERE expires_at <= UTC_TIMESTAMP()');
}

function panel_cookie_path(): string
{
    $scriptName = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/');
    $directory = rtrim(dirname($scriptName), '/.');
    return ($directory === '' ? '' : $directory) . '/';
}

function panel_cookie_is_secure(): bool
{
    return !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';
}

function panel_clear_remember_cookie(): void
{
    setcookie(PANEL_REMEMBER_COOKIE, '', [
        'expires' => time() - 3600,
        'path' => panel_cookie_path(),
        'secure' => panel_cookie_is_secure(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    unset($_COOKIE[PANEL_REMEMBER_COOKIE]);
}

function panel_parse_remember_cookie(): ?array
{
    $value = $_COOKIE[PANEL_REMEMBER_COOKIE] ?? '';
    if (!is_string($value) || !preg_match('/^([a-f0-9]{24}):([a-f0-9]{64})$/', $value, $matches)) {
        return null;
    }

    return ['selector' => $matches[1], 'validator' => $matches[2]];
}

function panel_forget_remember_token(PDO $pdo): void
{
    $token = panel_parse_remember_cookie();
    if ($token !== null) {
        $statement = $pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector');
        $statement->execute(['selector' => $token['selector']]);
    }

    panel_clear_remember_cookie();
}

function panel_issue_remember_token(PDO $pdo, int $userId): void
{
    panel_ensure_auth_schema($pdo);

    $selector = bin2hex(random_bytes(12));
    $validator = bin2hex(random_bytes(32));
    $validatorHash = hash('sha256', $validator);

    $statement = $pdo->prepare("
        INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at)
        VALUES (:user_id, :selector, :validator_hash, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))
    ");
    $statement->execute([
        'user_id' => $userId,
        'selector' => $selector,
        'validator_hash' => $validatorHash,
    ]);

    setcookie(PANEL_REMEMBER_COOKIE, $selector . ':' . $validator, [
        'expires' => time() + (PANEL_REMEMBER_DAYS * 86400),
        'path' => panel_cookie_path(),
        'secure' => panel_cookie_is_secure(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function panel_login_from_remember_cookie(PDO $pdo): ?array
{
    $token = panel_parse_remember_cookie();
    if ($token === null) {
        if (isset($_COOKIE[PANEL_REMEMBER_COOKIE])) {
            panel_clear_remember_cookie();
        }
        return null;
    }

    panel_ensure_auth_schema($pdo);
    $statement = $pdo->prepare("
        SELECT rt.validator_hash, au.id, au.username
        FROM remember_tokens rt
        INNER JOIN admin_users au ON au.id = rt.user_id
        WHERE rt.selector = :selector AND rt.expires_at > UTC_TIMESTAMP()
        LIMIT 1
    ");
    $statement->execute(['selector' => $token['selector']]);
    $row = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$row || !hash_equals((string) $row['validator_hash'], hash('sha256', $token['validator']))) {
        $delete = $pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector');
        $delete->execute(['selector' => $token['selector']]);
        panel_clear_remember_cookie();
        return null;
    }

    $delete = $pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector');
    $delete->execute(['selector' => $token['selector']]);
    panel_issue_remember_token($pdo, (int) $row['id']);

    return ['id' => (int) $row['id'], 'username' => (string) $row['username']];
}
