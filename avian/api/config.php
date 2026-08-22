<?php
// AvianVisitors - read/write a small, whitelisted subset of BirdNET-Pi
// settings from the admin overlay's settings panel. Fetched by the
// frontend at /avian/api/config.php.
//
// Endpoints:
//   GET  -> returns current values as JSON.
//   POST -> JSON body with any whitelisted key. Writes through to
//           birdnet.conf and restarts birdnet_analysis + birdnet_recording
//           so the changes take effect immediately.
//
// Direct requests on the station's private address are available without a
// password. Forwarded and public-host requests verify BirdNET-Pi's configured
// admin password here.
//
// Restart requires passwordless sudo for the caddy user that runs
// php-fpm, dropped in place by install_services.sh at
// /etc/sudoers.d/020_avian-admin.

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

require_once __DIR__ . '/admin-auth.php';
avian_require_admin();

// Path layout: /home/{USER}/BirdNET-Pi/avian/api/config.php
$BIRDNETPI_DIR = dirname(__DIR__, 2);
$CONF_PATH     = "$BIRDNETPI_DIR/birdnet.conf";
$ADMIN_CONTROL = getenv('AV_ADMIN_CONTROL') ?: '/usr/local/sbin/avian-admin-control';

// Whitelist: { config_key => { type, min?, max?, restart? } }
$ALLOWED = [
    'CONFIDENCE'         => ['type' => 'float', 'min' => 0.05, 'max' => 0.99, 'restart' => true],
    'SENSITIVITY'        => ['type' => 'float', 'min' => 0.5,  'max' => 1.5,  'restart' => true],
    // Floor matches upstream: 0.0 admits every label in the model and
    // silently disables the range filter for the whole station.
    'SF_THRESH'          => ['type' => 'float', 'min' => 0.0005, 'max' => 0.99, 'restart' => true],
    'OVERLAP'            => ['type' => 'float', 'min' => 0.0,  'max' => 2.5,  'restart' => true],
    'MAX_FILES_SPECIES'  => ['type' => 'int',   'min' => 0,    'max' => 100000],
    'FULL_DISK'          => ['type' => 'enum',  'values' => ['purge', 'keep']],
    // Display preference, no service restart: the collage picks it up on its
    // next fetch and the frame publisher on its next tick.
    'COLLAGE_LABELS'     => ['type' => 'enum',  'values' => ['on', 'off']],
    'PURGE_THRESHOLD'    => ['type' => 'int',   'min' => 50,   'max' => 99],
    'LATITUDE'           => ['type' => 'float', 'min' => -90,  'max' => 90, 'restart' => true],
    'LONGITUDE'          => ['type' => 'float', 'min' => -180, 'max' => 180, 'restart' => true],
    'SITE_NAME'          => ['type' => 'string', 'maxlen' => 60],
    // Secrets: writable like any setting, but NEVER echoed back on GET -
    // the response carries only a set/unset flag. Consumed by the
    // illustration pipeline (generate.php passes them by env).
    'GEMINI_API_KEY'     => ['type' => 'secret', 'maxlen' => 200],
    'EBIRD_API_KEY'      => ['type' => 'secret', 'maxlen' => 120],
];

function read_conf(string $path): array {
    if (!is_readable($path)) return [];
    $out = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES) as $line) {
        if (!$line || $line[0] === '#') continue;
        if (preg_match('/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/i', $line, $m)) {
            $val = trim($m[2]);
            if (strlen($val) >= 2 && $val[0] === '"' && substr($val, -1) === '"') {
                $val = substr($val, 1, -1);
            }
            $out[$m[1]] = $val;
        }
    }
    return $out;
}

function run_admin_control(string $control, array $arguments, ?string $input = null): array {
    if (!is_executable($control)) {
        return ['ok' => false, 'error' => 'admin control is not installed'];
    }
    $command = ['/usr/bin/sudo', '-n', $control];
    foreach ($arguments as $argument) $command[] = (string)$argument;
    $pipes = [];
    $process = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes, null, null, ['bypass_shell' => true]);
    if (!is_resource($process)) {
        return ['ok' => false, 'error' => 'could not start admin control'];
    }

    $writeOk = true;
    if ($input !== null && $input !== '') {
        $offset = 0;
        $length = strlen($input);
        while ($offset < $length) {
            $written = @fwrite($pipes[0], substr($input, $offset));
            if (!is_int($written) || $written < 1) {
                $writeOk = false;
                break;
            }
            $offset += $written;
        }
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($process);
    if (!$writeOk) {
        return ['ok' => false, 'error' => 'could not send config to admin control'];
    }

    $decoded = json_decode(is_string($stdout) ? $stdout : '', true);
    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'admin control returned an invalid response'];
    }
    if ($code !== 0 || empty($decoded['ok'])) {
        return ['ok' => false, 'error' => (string)($decoded['error'] ?? 'admin control failed')];
    }
    return $decoded;
}

// Tight allowlist for string fields. The root-owned writer repeats the same
// validation before it touches birdnet.conf.
function safe_string_value(string $v): bool {
    return (bool)preg_match("/^[A-Za-z0-9 _.,'-]*$/u", $v);
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    $conf = read_conf($CONF_PATH);
    $out = [];
    $secrets = [];
    foreach ($ALLOWED as $k => $spec) {
        if ($spec['type'] === 'secret') {
            // Never return the value; the UI only needs to know it's set.
            $secrets[$k] = ($conf[$k] ?? '') !== '';
            continue;
        }
        if (!array_key_exists($k, $conf)) continue;
        $v = $conf[$k];
        if ($spec['type'] === 'float') $v = (float)$v;
        elseif ($spec['type'] === 'int') $v = (int)$v;
        $out[$k] = $v;
    }
    echo json_encode([
        'values'   => $out,
        'secrets'  => $secrets,
        'meta'     => $ALLOWED,
        'preserve' => (int)($conf['MAX_FILES_SPECIES'] ?? 0) >= 10000,
    ]);
    exit;
}

if ($method === 'POST') {
    avian_require_json_action();
    $raw = file_get_contents('php://input');
    $body = json_decode((string)$raw, true);
    if (!is_array($body)) {
        http_response_code(400);
        echo json_encode(['error' => 'bad json']);
        exit;
    }
    $updates = [];
    $errors = [];
    foreach ($body as $k => $v) {
        // 'preserve' is a UI-side convenience flag handled below - skip it here.
        if ($k === 'preserve') continue;
        if (!isset($ALLOWED[$k])) { $errors[$k] = 'unknown'; continue; }
        $spec = $ALLOWED[$k];
        if ($spec['type'] === 'float') {
            if (!is_int($v) && !is_float($v)) { $errors[$k] = 'not a number'; continue; }
            $v = (float)$v;
            if ($v < ($spec['min'] ?? -INF) || $v > ($spec['max'] ?? INF)) { $errors[$k] = 'out of range'; continue; }
        } elseif ($spec['type'] === 'int') {
            if (!is_int($v)) { $errors[$k] = 'not an integer'; continue; }
            if ($v < ($spec['min'] ?? -PHP_INT_MAX) || $v > ($spec['max'] ?? PHP_INT_MAX)) { $errors[$k] = 'out of range'; continue; }
        } elseif ($spec['type'] === 'enum') {
            if (!is_string($v)) { $errors[$k] = 'invalid value'; continue; }
            if (!in_array($v, $spec['values'], true)) { $errors[$k] = 'invalid value'; continue; }
        } elseif ($spec['type'] === 'string') {
            if (!is_string($v)) { $errors[$k] = 'not a string'; continue; }
            $v = (string)$v;
            if (strlen($v) > ($spec['maxlen'] ?? 200)) { $errors[$k] = 'too long'; continue; }
            // String fields land in birdnet.conf which upstream shell tools
            // source. Keep shell metacharacters out before the root writer
            // repeats the same validation.
            if (!safe_string_value($v)) { $errors[$k] = 'invalid characters'; continue; }
        } elseif ($spec['type'] === 'secret') {
            if (!is_string($v)) { $errors[$k] = 'not a string'; continue; }
            $v = trim((string)$v);
            if (strlen($v) > ($spec['maxlen'] ?? 200)) { $errors[$k] = 'too long'; continue; }
            // API tokens need a wider character set than SITE_NAME, but still
            // stay inside a fixed allowlist. Empty string clears the key.
            if (!preg_match('/^[A-Za-z0-9_\-.\/+=:]*$/', $v)) { $errors[$k] = 'invalid characters'; continue; }
        }
        $updates[$k] = $v;
    }
    if ($errors) {
        http_response_code(400);
        echo json_encode(['error' => 'validation', 'fields' => $errors]);
        exit;
    }

    // Convenience flag: "preserve" toggle in the UI sets a high recording cap.
    // Off restores the installer default (0 = no per-species cap) rather
    // than 50, which would delete recordings a user never asked to lose.
    if (isset($body['preserve'])) {
        if (!is_bool($body['preserve'])) {
            http_response_code(400);
            echo json_encode(['error' => 'validation', 'fields' => ['preserve' => 'not a boolean']]);
            exit;
        }
        $updates['MAX_FILES_SPECIES'] = $body['preserve'] ? 99999 : 0;
    }

    if ($updates) {
        $payload = '';
        foreach ($updates as $key => $value) {
            $payload .= $key . "\0" . (string)$value . "\0";
        }
        $result = run_admin_control(
            $ADMIN_CONTROL,
            ['config-set-stdin', (string)count($updates)],
            $payload
        );
        if (empty($result['ok'])) {
            http_response_code(500);
            echo json_encode(['error' => $result['error'] ?? 'config write failed']);
            exit;
        }
    }

    // Restart services if any setting requires it.
    $needsRestart = false;
    foreach (array_keys($updates) as $k) {
        if (!empty($ALLOWED[$k]['restart'])) { $needsRestart = true; break; }
    }
    $restarted = [];
    if ($needsRestart) {
        foreach (['birdnet_analysis', 'birdnet_recording'] as $svc) {
            $result = run_admin_control($ADMIN_CONTROL, ['restart', $svc]);
            $restarted[$svc] = !empty($result['ok']);
        }
        if (in_array(false, $restarted, true)) {
            http_response_code(500);
            echo json_encode([
                'ok' => false,
                'error' => 'settings saved, but a BirdNET service did not restart',
                'restarted' => $restarted,
            ]);
            exit;
        }
    }
    // Don't echo secret values back; report which keys changed only.
    $shown = [];
    foreach ($updates as $k => $v) {
        $shown[$k] = (($ALLOWED[$k]['type'] ?? '') === 'secret') ? '(saved)' : $v;
    }
    echo json_encode(['ok' => true, 'updates' => $shown, 'restarted' => $restarted]);
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'method not allowed']);
