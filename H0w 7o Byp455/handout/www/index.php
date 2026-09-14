<?php
require __DIR__ . '/cleanup.php';
require __DIR__ . '/ratelimit.php';

$upload_dir = __DIR__ . '/uploads/';
$sig_db = '/opt/sigs/custom.ndb';

cleanup_expired_uploads($upload_dir);

function render_listing($upload_dir) {
    $names = [];
    if (is_dir($upload_dir)) {
        foreach (scandir($upload_dir) as $n) {
            if ($n === '.' || $n === '..' || $n === '.gitkeep') continue;
            $names[] = $n;
        }
    }
    sort($names);
    if (empty($names)) {
        return '<p class="leadish">No one has uploaded anything yet.</p>';
    }
    $items = '';
    foreach ($names as $n) {
        $safe = htmlspecialchars($n, ENT_QUOTES);
        $items .= "<li><a href=\"/run.php?f={$safe}\">/run.php?f={$safe}</a></li>";
    }
    return "<ul class=\"leadish\">{$items}</ul>";
}

$message_html = '';
$status_code = 200;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (rate_limited('upload', 10.0, 3)) {
        $message_html = '<div class="alert alert-warning mt-3">🐢 Slow down. Try again in a few seconds.</div>';
        $status_code = 429;
    } elseif (!isset($_FILES['webshell']) || $_FILES['webshell']['error'] === UPLOAD_ERR_NO_FILE || $_FILES['webshell']['name'] === '') {
        $message_html = '<div class="alert alert-warning mt-3">No file selected.</div>';
    } elseif (!preg_match('/\.php$/i', $_FILES['webshell']['name'])) {
        $message_html = '<div class="alert alert-warning mt-3">When in Rome, do as the Romans do.</div>';
    } else {
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        $safe_name = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($_FILES['webshell']['name']));
        $tmp_name = $upload_dir . '.tmp-' . bin2hex(random_bytes(16)) . '.php';
        move_uploaded_file($_FILES['webshell']['tmp_name'], $tmp_name);

        $scan_out = [];
        $rc = 0;
        exec('clamscan --no-summary -d ' . escapeshellarg($sig_db) . ' ' . escapeshellarg($tmp_name) . ' 2>&1', $scan_out, $rc);

        if ($rc === 0) {
            $dest_name = bin2hex(random_bytes(4)) . '_' . $safe_name;
            rename($tmp_name, $upload_dir . $dest_name);
            $safe_dest = htmlspecialchars($dest_name, ENT_QUOTES);
            $message_html = '<div class="alert alert-success mt-3">'
                . "✅ Upload accepted, the AV had no objections. <a href=\"/run.php?f={$safe_dest}\">/run.php?f={$safe_dest}</a>"
                . '</div>';
        } else {
            @unlink($tmp_name);
            $message_html = '<div class="alert alert-danger mt-3">'
                . '🚨 Malicious content detected.'
                . '</div>';
        }
    }
}

$listing_html = render_listing($upload_dir);
http_response_code($status_code);
?>
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="author" content="CHW">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>H0w 7o Byp455</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+TC:wght@400;600;700&family=Press+Start+2P&display=swap" rel="stylesheet">

  <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
        integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.2/css/all.min.css"
        integrity="sha512-HK5fgLBL+xu6dm/Ii3z4xhlSUyZgTT9tuc/hSrtw6uzJOvgRr2a9jyxxT1ely+B+xFAmJKVSTbpM/CuL7qxO8w==" crossorigin="anonymous" />

  <link rel="stylesheet" href="/assets/css/main.css">
  <link rel="icon" href="/assets/favicon.png"/>
</head>
<body>
  <div id="main" class="container">
    <div id="title-wrap" class="text-center">
      <div class="title-box">
        <h1 id="title">
          <i class="far fa-smile"></i>
          <b>H0w 7o Byp455</b>
          <i class="far fa-smile"></i>
        </h1>
      </div>
    </div>

    <header>
      <p class="subtitle">"AV can be a man's heaven, or a security researcher's hell."</p>
    </header>

    <div id="img-div" class="text-center">
      <img id="image" class="hero-img" src="/assets/cyberpunk.gif" alt="staring in the abyss">
    </div>

    <main class="mt-4">
      <section class="mb-3">
        <div class="chw-card">
          <h2 class="h4 mb-3"><i class="fas fa-door-open"></i> Welcome</h2>
          <p class="leadish">Hackers often use AI to carry out cyberattacks or other harmful activities.</p>
          <p> Feel free to learn from <a href="https://chw41.github.io/b1og/cybersec-2025-%E8%87%BA%E7%81%A3%E8%B3%87%E5%AE%89%E5%A4%A7%E6%9C%83-operations-security-opsec--%E7%B4%85%E9%9A%8A%E4%B8%8D%E8%A2%AB%E6%8A%93%E5%88%B0%E7%9A%84%E7%A7%98%E5%AF%86-steven-meow/">HERE</a>. (NO HINT)</p>
        </div>
      </section>

      <section class="mt-4">
        <div class="chw-card">
          <h2 class="h4 mb-3"><i class="fas fa-box-open"></i> Story</h2>
          <p>生魚片其實是死魚片</p>
          <p>等紅燈其實是等綠燈</p>
          <p>坐電梯其實是站電梯</p>
          <p>其實你最新的照片 是你最老的照片</p>
          <p></p>
          <p>原則上可以是不可以</p>
          <p>原則上不可以是可以</p>
        </div>
      </section>

      <section class="mt-4">
        <div class="chw-card">
          <h2 class="h4 mb-3"><i class="fas fa-box-open"></i> Hints</h2>
          <p>一寸光陰一寸金</p>
          <p>寸金難買市中心</p>
        </div>
      </section>

      <section class="mt-4">
        <div class="chw-card">
          <h2 class="h4 mb-3"><i class="fas fa-upload"></i> Upload</h2>
          <form method="POST" action="/" enctype="multipart/form-data">
            <div class="form-group">
              <input type="file" name="webshell" class="form-control-file" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Upload</button>
          </form>
          <?= $message_html ?>
        </div>
      </section>

      <section class="mt-4">
        <div class="chw-card">
          <h2 class="h4 mb-3"><i class="fas fa-folder-open"></i> Folder</h2>
          <?= $listing_html ?>
        </div>
      </section>
    </main>

    <section class="mt-4">
        <div class="chw-card">
          <h2 class="h4 mb-3"> <i class="fas fa-exclamation-circle"></i></i> Alert</h2>
          <p> 嚴重懷疑：</p>
          <p> ⚠ Your conversations have multiple flags for possible cybersecurity risk. Responses may take longer because extra safety checks are occurring. If you do security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber </p>
          <p> ⓘ This chat was flagged for possible cybersecurity risk </p>
          <p>If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program. https://chatgpt.com/cyber </p>
          <p></p>
          <p> ⚠ API Error: ALL models safeguards flagged this message. Our intentionally broad safeguards allow us to deliver more capabilities faster, but can sometimes flag legitimate cybersecurity work. Apply to the Cyber Verification Program to avoid these interruptions. Send feedback with /feedback or learn more:
https://support.claude.com/en/articles/...  </p>
        </div>
      </section>

    <footer class="site-footer">
      <p>&copy; H0w 7o Byp455</p>
    </footer>
  </div>

  <script src="//cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js"
          integrity="sha512-qTXRIMyZIFb8iQcfjXWCO8+M5Tbc38Qi5WzdPOYZHIlZpzBHG3L3by84BBBOiRGiEb7KKtAOAs5qYdUiZiQNNQ==" crossorigin="anonymous"></script>
</body>
</html>
