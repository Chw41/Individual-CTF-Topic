<?php
function rate_limited($action, $window, $max) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $store = sys_get_temp_dir() . '/ratelimit_' . $action . '_' . md5($ip) . '.json';
    $now = microtime(true);
    $hits = [];
    if (is_file($store)) {
        $hits = json_decode(@file_get_contents($store), true) ?: [];
    }
    $hits = array_values(array_filter($hits, fn($t) => $now - $t < $window));
    $hits[] = $now;
    @file_put_contents($store, json_encode($hits));
    return count($hits) > $max;
}
