<?php
session_start();

$configDir = __DIR__ . '/../key';
$configPath = $configDir . '/db_config.php';
require_once $configDir . '/config_crypto.php';
require_once $configDir . '/auth.php';

$remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';
if (PHP_SAPI !== 'cli' && !in_array($remoteAddress, ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit('For security reasons, the installer is only available from this computer.');
}

if (empty($_SESSION['install_csrf_token'])) {
    $_SESSION['install_csrf_token'] = bin2hex(random_bytes(32));
}

function ensure_config_dir(string $configDir): void {
    if (!is_dir($configDir) && !mkdir($configDir, 0755, true)) {
        die('Error: unable to create the key/ directory. Check the permissions.');
    }
}

function installation_is_complete(string $configPath): bool
{
    if (!is_file($configPath)) {
        return false;
    }

    try {
        $config = panel_load_db_config($configPath);
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            $config['host'],
            $config['dbname']
        );
        $pdo = new PDO($dsn, $config['user'], $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        $statement = $pdo->query('SELECT COUNT(*) FROM admin_users');
        return (int) $statement->fetchColumn() > 0;
    } catch (Throwable $e) {
        error_log('Installation status check failed: ' . $e->getMessage());
        return false;
    }
}

if (
    $_SERVER['REQUEST_METHOD'] !== 'POST' &&
    empty($_SESSION['installation_in_progress']) &&
    installation_is_complete($configPath)
) {
    header('Location: ../login.php');
    exit;
}
$alertStatus = "";
$alertMessage = isset($_GET['reason']) && $_GET['reason'] === 'database'
    ? 'The saved database configuration is invalid or the database is unavailable. Please enter valid details.'
    : '';

if (file_exists($configPath)) {
    try {
        $dbConfig = panel_load_db_config($configPath);
    } catch (Throwable $e) {
        error_log('Unable to load the database configuration: ' . $e->getMessage());
        $dbConfig = ['host' => '', 'user' => '', 'password' => '', 'dbname' => ''];
    }
} else {
    $dbConfig = [
        'host'     => '',
        'user'     => '',
        'password' => '',
        'dbname'   => ''
    ];
}

if (!isset($_SESSION['data']) || !is_array($_SESSION['data'])) {
    $_SESSION['data'] = [];
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['step'])) {
    if (
        !isset($_POST['csrf_token']) ||
        !is_string($_POST['csrf_token']) ||
        !hash_equals($_SESSION['install_csrf_token'], $_POST['csrf_token'])
    ) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    switch ($_POST['step']) {
        case 2:
            $hostInput     = isset($_POST['host']) ? trim($_POST['host']) : '';
            $userInput     = isset($_POST['user']) ? trim($_POST['user']) : '';
            $passwordInput = isset($_POST['password']) ? trim($_POST['password']) : '';
            $dbnameInput   = isset($_POST['dbname']) ? trim($_POST['dbname']) : '';

            $_SESSION['data']['host']     = htmlspecialchars($hostInput, ENT_QUOTES, 'UTF-8');
            $_SESSION['data']['user']     = htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
            // Never keep the database password longer than the current installation session.
            $_SESSION['data']['password'] = $passwordInput;
            $_SESSION['data']['dbname']   = htmlspecialchars($dbnameInput, ENT_QUOTES, 'UTF-8');

            if ($hostInput === '' || $userInput === '' || $dbnameInput === '') {
                die('Error: host, username and database name are required.');
            }

            if (!preg_match('/^[a-zA-Z0-9_]+$/', $dbnameInput)) {
                die('Error: invalid database name. Use only letters, numbers and underscores.');
            }

            try {
                $pdo = new PDO(
                    'mysql:host=' . $hostInput . ';charset=utf8mb4',
                    $userInput,
                    $passwordInput,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]
                );

                $sanitisedDbname = str_replace('`', '', $dbnameInput);

                $pdo->exec(
                    'CREATE DATABASE IF NOT EXISTS `' .
                    $sanitisedDbname .
                    '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
                );

                $alertStatus = "success";
            } catch (PDOException $e) {
                error_log('Error while creating the database: ' . $e->getMessage());

                die(
                    'MySQL error: ' .
                    htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8')
                );
            }

            ensure_config_dir($configDir);

            try {
                panel_write_db_config($configPath, [
                    'host' => $hostInput,
                    'user' => $userInput,
                    'password' => $passwordInput,
                    'dbname' => $dbnameInput,
                ]);
            } catch (Throwable $e) {
                error_log('Unable to save the encrypted configuration: ' . $e->getMessage());
                die('Error: unable to save the encrypted database configuration.');
            }

            $_SESSION['installation_in_progress'] = true;
            header('Location: setup.php?step=3');
            exit;

        case 3:
            $adminUserRaw     = isset($_POST['adminUser']) ? trim($_POST['adminUser']) : '';
            $adminPasswordRaw = isset($_POST['adminPassword']) ? trim($_POST['adminPassword']) : '';

            if ($adminUserRaw === '' || $adminPasswordRaw === '') {
                die('Error: admin username and password are required.');
            }

            if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $adminUserRaw)) {
                die('Error: the admin username must contain 3 to 50 characters using only letters, numbers or underscores.');
            }

            if (strlen($adminPasswordRaw) < 6) {
                die('Error: the admin password must contain at least 6 characters.');
            }

            if (file_exists($configPath)) {
                $dbConfig = panel_load_db_config($configPath);
            }

            $adminUser     = htmlspecialchars($adminUserRaw, ENT_QUOTES, 'UTF-8');
            $adminPassword = htmlspecialchars($adminPasswordRaw, ENT_QUOTES, 'UTF-8');

            try {
                $dsn = sprintf(
                    'mysql:host=%s;dbname=%s;charset=utf8mb4',
                    $dbConfig['host'],
                    $dbConfig['dbname']
                );

                $conn = new PDO(
                    $dsn,
                    $dbConfig['user'],
                    $dbConfig['password']
                );

                $conn->setAttribute(
                    PDO::ATTR_ERRMODE,
                    PDO::ERRMODE_EXCEPTION
                );

                $conn->exec("
                    CREATE TABLE IF NOT EXISTS admin_users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        password VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ");

                panel_ensure_auth_schema($conn);

                $sql = "INSERT INTO admin_users (username, password)
                        VALUES (:username, :password)";

                $stmt = $conn->prepare($sql);

                $stmt->execute([
                    'username' => $adminUserRaw,
                    'password' => password_hash(
                        $adminPasswordRaw,
                        PASSWORD_DEFAULT
                    )
                ]);

                $alertStatus = "success";

                unset($_SESSION['data']);

                $_SESSION['installation_complete'] = true;
                $_SESSION['cleanup_token'] = bin2hex(random_bytes(32));

                header('Location: setup.php?step=4');
                exit;
            } catch (PDOException $e) {
                error_log(
                    'Error while creating the admin account: ' .
                    $e->getMessage()
                );

                $alertStatus = "error";
            }

            break;
    }
}

$step = isset($_GET['step']) ? (int)$_GET['step'] : 1;
if ($step < 1 || $step > 4) {
    $step = 1;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0">

    <title>Installation Wizard</title>

    <link
        href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"
        rel="stylesheet">

    <link
        href="style.css"
        rel="stylesheet">

    <style>
        .progress-bar {
            width: <?php echo ($step / 4) * 100; ?>%;
        }

        .btn-right {
            display: flex;
            justify-content: flex-end;
        }

        .alert {
            display: none;
        }

        .alert-show {
            display: block;
        }
    </style>
</head>

<body>

<div class="custom-container">

    <div class="progress">
        <div
            id="progressBar"
            class="progress-bar"
            role="progressbar"
            aria-valuenow="<?php echo ($step / 4) * 100; ?>"
            aria-valuemin="0"
            aria-valuemax="100">
            Step <?php echo $step; ?> of 4
        </div>
    </div>

    <div
        id="step1"
        class="card"
        style="display: <?php echo ($step == 1) ? 'block' : 'none'; ?>">
        <div class="card-body text-center">

            <h5 class="card-title">
                Welcome to the Panel wizard!
            </h5>

            <p class="card-text">
                Make sure to follow the instructions to begin installation.
                If you need help, refer to the FAQ.
            </p>

            <div class="btn-right">
                <a
                    href="setup.php?step=2"
                    class="btn btn-primary"
                >
                    Next
                </a>
            </div>

        </div>
    </div>

    <div
        id="step2"
        class="card"
        style="display: <?php echo ($step == 2) ? 'block' : 'none'; ?>">
        <div class="card-body text-center">

            <h5 class="card-title">
                MySQL Information
            </h5>

            <?php if ($alertMessage !== ''): ?>
                <div class="alert alert-danger alert-show" role="alert">
                    <?php echo htmlspecialchars($alertMessage, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <form
                id="form2"
                method="post"
                action="setup.php">

                <input
                    type="hidden"
                    name="step"
                    value="2">
                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?php echo htmlspecialchars($_SESSION['install_csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                <div class="form-group row">

                    <label
                        for="host"
                        class="col-sm-4 col-form-label">
                        Hostname:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="text"
                            class="form-control"
                            id="host"
                            name="host"
                            value="<?php echo htmlspecialchars((string) ($dbConfig['host'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>"
                            required>
                    </div>
                </div>
                <div class="form-group row">

                    <label
                        for="user"
                        class="col-sm-4 col-form-label">
                        Username:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="text"
                            class="form-control"
                            id="user"
                            name="user"
                            value="<?php echo htmlspecialchars((string) ($dbConfig['user'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>"
                            required>
                    </div>
                </div>

                <div class="form-group row">

                    <label
                        for="password"
                        class="col-sm-4 col-form-label">
                        Password:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="password"
                            class="form-control"
                            id="password"
                            name="password">
                    </div>

                </div>

                <div class="form-group row">

                    <label
                        for="dbname"
                        class="col-sm-4 col-form-label">
                        Database Name:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="text"
                            class="form-control"
                            id="dbname"
                            name="dbname"
                            value="<?php echo htmlspecialchars((string) ($dbConfig['dbname'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>"
                            required>
                    </div>

                </div>

                <div
                    class="alert alert-success"
                    id="successAlert"
                    role="alert">
                    Connection successful! You can now continue to the next step.
                </div>

                <div class="btn-right">

                    <button
                        type="button"
                        class="btn btn-secondary"
                        onclick="testConnection()">
                        Test
                    </button>

                    <button
                        type="submit"
                        class="btn btn-primary"
                        id="nextBtn"
                        disabled>
                        Next
                    </button>
                </div>
            </form>
        </div>
    </div>
    <div
        id="step3"
        class="card"
        style="display: <?php echo ($step == 3) ? 'block' : 'none'; ?>">
        <div class="card-body text-center">
            <h5 class="card-title">
                Create Admin Account
            </h5>
            <form
                id="form3"
                method="post"
                action="setup.php">

                <input
                    type="hidden"
                    name="step"
                    value="3">
                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?php echo htmlspecialchars($_SESSION['install_csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                <div class="form-group row">

                    <label
                        for="adminUser"
                        class="col-sm-4 col-form-label">
                        Admin Username:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="text"
                            class="form-control"
                            id="adminUser"
                            name="adminUser"
                            required>
                    </div>
                </div>

                <div class="form-group row">

                    <label
                        for="adminPassword"
                        class="col-sm-4 col-form-label">
                        Admin Password:
                    </label>

                    <div class="col-sm-8">
                        <input
                            type="password"
                            class="form-control"
                            id="adminPassword"
                            name="adminPassword"
                            required>
                    </div>

                </div>

                <div class="btn-right">
                    <button
                        type="submit"
                        class="btn btn-primary">
                        Next
                    </button>
                </div>
            </form>
        </div>
    </div>

    <div
        id="step4"
        class="card"
        style="display: <?php echo ($step == 4) ? 'block' : 'none'; ?>">
        <div class="card-body text-center">

            <h5 class="card-title">
                Panel Installation Successful!
            </h5>

            <p class="card-text">
                You can now access your panel login.
                The /install folder will be removed automatically before redirection.
            </p>

            <p id="redirectText">
                You will be automatically redirected in
                <span id="countdown">3</span>
                seconds...
            </p>

            <p>
                <a href="../login.php">
                    Click here if you are not redirected
                </a>
            </p>

            <div
                class="alert alert-danger"
                id="cleanupError"
                role="alert">
                Automatic removal failed. Remove the /install folder manually before exposing the site.
            </div>

            <div
                class="alert alert-success mt-3 alert-show"
                role="alert">
                The installation has finished successfully!
            </div>

            <div
                class="alert alert-warning mt-3"
                role="alert">
                This is an example warning. Please read carefully.
            </div>

            <div
                class="alert alert-success alert-show"
                id="successAlertFinal"
                role="alert">
                Installation successful!
            </div>

        </div>
    </div>

</div>

<script>
function testConnection() {
    const host = document.querySelector('[name="host"]').value;
    const user = document.querySelector('[name="user"]').value;
    const password = document.querySelector('[name="password"]').value;
    const dbname = document.querySelector('[name="dbname"]').value;

    const formData = new FormData();

    formData.append('host', host);
    formData.append('user', user);
    formData.append('password', password);
    formData.append('dbname', dbname);
    formData.append(
        'csrf_token',
        <?php echo json_encode($_SESSION['install_csrf_token'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>
    );

    fetch('test_connection.php', {
        method: 'POST',
        body: formData
    })
    .then(async response => {
        const text = await response.text();

        try {
            return JSON.parse(text);
        } catch (e) {
            throw new Error(
                'Invalid server response: ' + text
            );
        }
    })
    .then(data => {
        if (data.success) {
            const successAlert =
                document.getElementById('successAlert');

            successAlert.textContent =
                data.message ||
                'Connection successful! You can continue.';

            successAlert.classList.add('alert-show');

            document.querySelector('#nextBtn').disabled = false;
        } else {
            alert(
                data.message ||
                'Unable to connect to the database.'
            );

            document.querySelector('#nextBtn').disabled = true;
        }
    })
    .catch(error => {
        console.error('Error:', error);

        alert(
            error.message ||
            'An error occurred while testing the connection.'
        );

        document.querySelector('#nextBtn').disabled = true;
    });
}

async function cleanupInstallerAndRedirect() {
    const formData = new FormData();
    formData.append(
        'cleanup_token',
        <?php echo json_encode($_SESSION['cleanup_token'] ?? '', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>
    );

    try {
        const response = await fetch('../finalize_install.php', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Installer cleanup failed.');
        }
        window.location.href = '../login.php';
    } catch (error) {
        console.error('Installer cleanup error:', error);
        document.getElementById('cleanupError').classList.add('alert-show');
    }
}

window.onload = function() {
    if (<?php echo $step; ?> === 4) {
        document
            .getElementById('successAlertFinal')
            .classList
            .add('alert-show');

        let countdown = 3;

        const countdownElement =
            document.getElementById('countdown');

        const interval = setInterval(() => {
            if (countdown > 0) {
                countdown--;
                countdownElement.textContent = countdown;
            } else {
                clearInterval(interval);
                cleanupInstallerAndRedirect();
            }
        }, 1000);
    }
};
</script>

</body>
</html>
