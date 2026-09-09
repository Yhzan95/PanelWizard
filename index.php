<?php
session_start();

$configPath = __DIR__ . '/key/db_config.php';

if (!file_exists($configPath)) {
    header("Location: install/setup.php");
    exit();
}

if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Yhzany95 Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">
            Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?>!
        </h1>

        <p class="text-center">
            This is your secure dashboard.
        </p>

        <div class="text-center mt-4">
            <form method="post" action="logout.php">
                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                <button type="submit" class="btn btn-danger">Log out</button>
            </form>
        </div>
    </div>
</body>
</html>
