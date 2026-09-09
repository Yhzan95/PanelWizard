<?php
declare(strict_types=1);

const PANEL_CONFIG_CIPHER = 'aes-256-gcm';

function panel_secret_directory(): string
{
    $configured = getenv('PANEL_SECRET_DIR');
    if (is_string($configured) && trim($configured) !== '') {
        return rtrim($configured, "\\/");
    }

    $documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if (is_string($documentRoot) && trim($documentRoot) !== '') {
        return dirname(rtrim($documentRoot, "\\/")) . DIRECTORY_SEPARATOR . 'panel-secrets';
    }

    // CLI fallback: key/ -> application -> htdocs -> server root.
    return dirname(__DIR__, 3) . DIRECTORY_SEPARATOR . 'panel-secrets';
}

function panel_ensure_secret_directory(): string
{
    $directory = panel_secret_directory();

    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create the secret directory outside the web root.');
    }

    @chmod($directory, 0700);
    return $directory;
}

function panel_write_db_config(string $configPath, array $config): void
{
    foreach (['host', 'user', 'password', 'dbname'] as $requiredKey) {
        if (!array_key_exists($requiredKey, $config) || !is_string($config[$requiredKey])) {
            throw new InvalidArgumentException('Invalid database configuration.');
        }
    }

    if (!function_exists('openssl_encrypt')) {
        throw new RuntimeException('The OpenSSL PHP extension is required to encrypt the configuration.');
    }

    $secretDirectory = panel_ensure_secret_directory();
    $keyId = bin2hex(random_bytes(16));
    $key = random_bytes(32);
    $keyPath = $secretDirectory . DIRECTORY_SEPARATOR . $keyId . '.key';

    if (file_put_contents($keyPath, base64_encode($key), LOCK_EX) === false) {
        throw new RuntimeException('Unable to save the encryption key outside the web root.');
    }
    @chmod($keyPath, 0600);

    $iv = random_bytes(12);
    $tag = '';
    $plainText = json_encode($config, JSON_THROW_ON_ERROR);
    $cipherText = openssl_encrypt(
        $plainText,
        PANEL_CONFIG_CIPHER,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($cipherText === false) {
        @unlink($keyPath);
        throw new RuntimeException('Unable to encrypt the database configuration.');
    }

    $payload = [
        'format' => 'encrypted-v1',
        'key_id' => $keyId,
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($cipherText),
    ];

    $content = "<?php\nreturn " . var_export($payload, true) . ";\n";
    if (file_put_contents($configPath, $content, LOCK_EX) === false) {
        @unlink($keyPath);
        throw new RuntimeException('Unable to save the encrypted database configuration.');
    }
    @chmod($configPath, 0640);
}

function panel_load_db_config(string $configPath): array
{
    if (!is_file($configPath)) {
        throw new RuntimeException('Database configuration not found.');
    }

    $payload = include $configPath;
    if (!is_array($payload)) {
        throw new RuntimeException('Invalid database configuration file.');
    }

    // Migrate the previous clear-text format on first use.
    if (isset($payload['host'], $payload['user'], $payload['password'], $payload['dbname'])) {
        panel_write_db_config($configPath, $payload);
        return $payload;
    }

    foreach (['format', 'key_id', 'iv', 'tag', 'ciphertext'] as $requiredKey) {
        if (!isset($payload[$requiredKey]) || !is_string($payload[$requiredKey])) {
            throw new RuntimeException('Invalid encrypted database configuration.');
        }
    }

    if ($payload['format'] !== 'encrypted-v1' || !preg_match('/^[a-f0-9]{32}$/', $payload['key_id'])) {
        throw new RuntimeException('Unsupported encrypted database configuration.');
    }

    $keyPath = panel_secret_directory() . DIRECTORY_SEPARATOR . $payload['key_id'] . '.key';
    $encodedKey = @file_get_contents($keyPath);
    $key = is_string($encodedKey) ? base64_decode(trim($encodedKey), true) : false;
    $iv = base64_decode($payload['iv'], true);
    $tag = base64_decode($payload['tag'], true);
    $cipherText = base64_decode($payload['ciphertext'], true);

    if ($key === false || strlen($key) !== 32 || $iv === false || $tag === false || $cipherText === false) {
        throw new RuntimeException('The database encryption key is missing or invalid.');
    }

    $plainText = openssl_decrypt(
        $cipherText,
        PANEL_CONFIG_CIPHER,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plainText === false) {
        throw new RuntimeException('Unable to decrypt the database configuration.');
    }

    $config = json_decode($plainText, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($config)) {
        throw new RuntimeException('Invalid decrypted database configuration.');
    }

    return $config;
}
