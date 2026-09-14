<?php
require __DIR__ . '/ratelimit.php';

error_reporting(E_ALL);
ini_set('display_errors', '1');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(404);
    exit;
}

if (rate_limited('oracle', 2.0, 2000)) {
    http_response_code(429);
    exit;
}

$sample = $_POST['sample'] ?? '';
hash_file('sha256', $sample);
