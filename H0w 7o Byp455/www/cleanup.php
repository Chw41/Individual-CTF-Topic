<?php
function cleanup_expired_uploads($upload_dir, $ttl_seconds = 180) {
    if (!is_dir($upload_dir)) {
        return;
    }
    $now = time();
    foreach (scandir($upload_dir) as $name) {
        if ($name === '.' || $name === '..' || $name === '.gitkeep') {
            continue;
        }
        if (str_starts_with($name, '.tmp-')) {
            continue;
        }
        $path = $upload_dir . $name;
        if (is_file($path) && ($now - filemtime($path)) > $ttl_seconds) {
            @unlink($path);
        }
    }
}
