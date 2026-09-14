<?php
require __DIR__ . '/cleanup.php';

$upload_dir = __DIR__ . '/uploads/';
cleanup_expired_uploads($upload_dir);

$f = $_GET['f'] ?? '';
$safe_name = basename($f);
$path = $upload_dir . $safe_name;

if (!is_file($path) || !preg_match('/\.php$/i', $safe_name)) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "Not found.";
    exit;
}

$c = $_GET['c'] ?? '';

$cmd = 'sudo -n -u appuser /usr/local/bin/php -f ' . escapeshellarg($path)
     . ' -- ' . escapeshellarg($c) . ' 2>&1';
$output = [];
$rc = 0;
exec($cmd, $output, $rc);

header('Content-Type: text/plain');
$body = implode("\n", $output);
echo $body !== '' ? $body : '(no output)';
