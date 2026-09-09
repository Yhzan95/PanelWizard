<?php
session_start();

$securityDirectory = __DIR__ . '/key';
require_once $securityDirectory . '/config_crypto.php';
require_once $securityDirectory . '/auth.php';

$configPath = __DIR__ . '/key/db_config.php';
$setupPath = __DIR__ . '/install/setup.php';

if (!file_exists($configPath)) {
    if (is_file($setupPath)) {
        header('Location: install/setup.php');
        exit;
    }

    http_response_code(503);
    exit('The application is not configured and the installer is unavailable.');
}

try {
    $dbConfig = panel_load_db_config($configPath);
    if (
        empty($dbConfig['host']) ||
        empty($dbConfig['user']) ||
        !isset($dbConfig['password']) ||
        empty($dbConfig['dbname'])
    ) {
        throw new RuntimeException('Incomplete database configuration.');
    }

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
} catch (Throwable $e) {
    error_log(
        'Database connection error: ' .
        $e->getMessage()
    );

    if (is_file($setupPath)) {
        header('Location: install/setup.php?step=2&reason=database');
        exit;
    }

    http_response_code(503);
    exit('The database is temporarily unavailable. Contact the administrator.');
}

if (isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$rememberedUser = panel_login_from_remember_cookie($conn);
if ($rememberedUser !== null) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $rememberedUser['id'];
    $_SESSION['user'] = $rememberedUser['username'];
    header('Location: index.php');
    exit;
}

$error = "";

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(
        random_bytes(32)
    );
}
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (
        !isset($_POST['csrf_token']) ||
        !is_string($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    $usernameRaw = $_POST['username'] ?? '';
    $passwordRaw = $_POST['password'] ?? '';
    $rememberMe = isset($_POST['remember_me']) && $_POST['remember_me'] === '1';
    $usernameRaw = trim($usernameRaw);

    if (
        strlen($usernameRaw) > 50 ||
        !preg_match('/^[a-zA-Z0-9_]+$/', $usernameRaw)
    ) {
        die("Invalid username format.");
    }

    if ($_SESSION['login_attempts'] >= 5) {
        die("Too many failed login attempts. Please try again later.");
    }

    try {
        $sql = "
            SELECT *
            FROM admin_users
            WHERE username = :username
            LIMIT 1
        ";

        $stmt = $conn->prepare($sql);

        $stmt->bindParam(
            ':username',
            $usernameRaw,
            PDO::PARAM_STR
        );

        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            $user &&
            password_verify(
                $passwordRaw,
                $user['password']
            )
        ) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['user'] = $user['username'];
            $_SESSION['login_attempts'] = 0;

            if ($rememberMe) {
                panel_issue_remember_token($conn, (int) $user['id']);
            } else {
                panel_forget_remember_token($conn);
            }

            header("Location: index.php");
            exit();
        } else {
            $_SESSION['login_attempts']++;

            error_log(
                "Failed login attempt for '" .
                $usernameRaw .
                "' from IP: " .
                ($_SERVER['REMOTE_ADDR'] ?? '')
            );

            $error = "Incorrect username or password.";
        }
    } catch (PDOException $e) {
        error_log(
            "PDO error: " .
            $e->getMessage()
        );

        $error = "Database connection error.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0">
    <title>Login - SavazH Panel</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css"
        rel="stylesheet">
    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body,
        html {
            height: 100%;
            margin: 0;
            font-family: Arial, sans-serif;
        }
        .container {
            background-color: #f5f5f5;
            border-radius: 10px;
            padding: 20px;
            max-width: 400px;
        }
        .gradient-bg {
            animation: gradient 15s ease infinite;
            background: linear-gradient(
                -45deg,
                #ee7752,
                #e73c7e,
                #23a6d5,
                #23d5ab
            );
            background-size: 400% 400%;
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        @keyframes gradient {
            0% {
                background-position: 0% 50%;
            }

            50% {
                background-position: 100% 50%;
            }

            100% {
                background-position: 0% 50%;
            }
        }
    </style>
</head>

<body>

<div class="gradient-bg">

    <div class="container">

        <?php if (!empty($error)): ?>
            <div
                class="alert alert-danger"
                role="alert">
                <?php echo $error; ?>
            </div>
        <?php endif; ?>
        <div class="row justify-content-center">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header text-center">
                        <h3>Login</h3>
                    </div>
                    <div class="card-body">
                        <form
                            id="loginForm"
                            method="post"
                            action="login.php">

                            <div class="mb-3 text-center">

                                <label
                                    for="username"
                                    class="form-label">
                                    Username
                                </label>
                                <input
                                    type="text"
                                    class="form-control mx-auto"
                                    id="username"
                                    name="username"
                                    required>
                            </div>
                            <div class="mb-3 text-center">
                               <label
                                    for="password"
                                    class="form-label">
                                    Password
                                </label>
                                <div class="input-group mx-auto">
                                    <input
                                        type="password"
                                        class="form-control"
                                        id="password"
                                        name="password"
                                        required>
                                    <button
                                        type="button"
                                        class="btn btn-outline-secondary"
                                        id="togglePassword">
                                        <i class="fas fa-eye"></i>
                                    </button>
               </div>

                            </div>

                            <div class="mb-3 form-check d-flex justify-content-center align-items-center">

                                <input
                                    type="checkbox"
                                    class="form-check-input"
                                    id="rememberMe"
                                    name="remember_me"
                                    value="1">

                                <label
                                    class="form-check-label mx-2 mb-0"
                                    for="rememberMe">
                                    Remember me
                                </label>

                            </div>

                            <input
                                type="hidden"
                                name="csrf_token"
                                value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                            <div class="text-center">

                                <button
                                    type="submit"
                                    class="btn btn-primary">
                                    Log in
                                </button>

                            </div>

                        </form>

                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document
    .getElementById('togglePassword')
    .addEventListener('click', function () {
        const password =
            document.getElementById('password');
        const type =
            password.getAttribute('type') === 'password'
                ? 'text'
                : 'password';
        password.setAttribute('type', type);
        this
            .querySelector('i')
            .classList
            .toggle('fa-eye');
        this
            .querySelector('i')
            .classList
            .toggle('fa-eye-slash');
    });
</script>

</body>
</html>
