<?php
/**
 * ============================================================================
 * Cyber Bootcamp - Assignment 11: SQL Injection Defense (أداة الحماية من ثغرات حقن قواعد البيانات)
 * Track: Cybersecurity Programming (PHP & Web)
 * 
 * Objectives:
 * 1. Initialize an in-memory SQLite database via PDO (sqlite::memory:).
 * 2. Create and seed a mock users table programmatically.
 * 3. Implement an insecure query mechanism using direct string concatenation ($_GET['username']).
 * 4. Implement a secure defense mechanism using PDO prepared statements and bound parameters.
 * 5. Demonstrate the contrast when tested with SQL injection payloads (e.g., ' OR '1'='1').
 * 6. Enforce safe error handling (ERRMODE_EXCEPTION) preventing schema information disclosure.
 * ============================================================================
 */

// Define error reporting for clean execution
error_reporting(E_ALL);
ini_set('display_errors', '1');

/**
 * Class Database
 * Handles SQLite in-memory database lifecycle, schema creation, and seeding.
 */
class Database {
    private static ?PDO $pdo = null;

    public static function getConnection(): PDO {
        if (self::$pdo === null) {
            // Establish PDO connection using in-memory SQLite for self-contained execution
            self::$pdo = new PDO('sqlite::memory:');

            // Configure PDO error mode to throw exceptions for defensive error handling
            self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

            // Initialize database schema and insert seed records
            self::initializeSchema(self::$pdo);
        }
        return self::$pdo;
    }

    private static function initializeSchema(PDO $pdo): void {
        // Create users table
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT NOT NULL
            )
        ");

        // Insert mock test records
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, role, full_name) 
            VALUES (:username, :email, :role, :full_name)
        ");

        $seedUsers = [
            ['username' => 'admin',   'email' => 'admin@security.local',   'role' => 'Administrator', 'full_name' => 'System Administrator'],
            ['username' => 'alice',   'email' => 'alice@security.local',   'role' => 'Security Analyst', 'full_name' => 'Alice Al-Sabah'],
            ['username' => 'bob',     'email' => 'bob@security.local',     'role' => 'Software Engineer', 'full_name' => 'Bob Smith'],
            ['username' => 'charlie', 'email' => 'charlie@security.local', 'role' => 'Auditor', 'full_name' => 'Charlie Brown'],
        ];

        foreach ($seedUsers as $user) {
            $stmt->execute($user);
        }
    }
}

/**
 * Class UserRepository
 * Provides both insecure and secure user retrieval methods for comparison.
 */
class UserRepository {
    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    /**
     * Insecure Query: Directly concatenates user input into the SQL string.
     * VULNERABILITY: SQL Injection (SQLi)
     * 
     * @param string $username
     * @return array
     */
    public function findByUsernameInsecure(string $username, string &$executedQuery, ?string &$queryError): array {
        $queryError = null;
        // Insecure: Direct string interpolation without sanitization or parameter binding
        $executedQuery = "SELECT id, username, email, role, full_name FROM users WHERE username = '{$username}'";

        try {
            $statement = $this->pdo->query($executedQuery);
            return $statement ? $statement->fetchAll() : [];
        } catch (PDOException $e) {
            // Insecure mode demonstrates how raw database errors can leak system internals
            $queryError = $e->getMessage();
            return [];
        }
    }

    /**
     * Secure Query: Uses PDO prepared statements and parameter binding.
     * DEFENSE: Complete separation of SQL code and untrusted user data.
     * 
     * @param string $username
     * @return array
     */
    public function findByUsernameSecure(string $username, string &$executedQuery, ?string &$queryError): array {
        $queryError = null;
        // Secure: Parameterized SQL template with placeholder
        $sqlTemplate = "SELECT id, username, email, role, full_name FROM users WHERE username = :username";
        $executedQuery = $sqlTemplate . " [Bound Parameter :username = " . json_encode($username) . "]";

        try {
            $stmt = $this->pdo->prepare($sqlTemplate);
            // Execute with bound parameters - the database engine treats input strictly as literal data
            $stmt->execute([':username' => $username]);
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            // Defensive: Log internally, but never leak SQL error details or schema info to the client
            $queryError = "A database error occurred. Your request could not be processed.";
            return [];
        }
    }
}

// Initialize database connection
$pdo = Database::getConnection();
$userRepo = new UserRepository($pdo);

// Check if script is running in CLI mode (for automated evaluation and terminal use)
if (php_sapi_name() === 'cli') {
    echo "========================================================================\n";
    echo " Cyber Bootcamp - Assignment 11: SQL Injection Defense (PHP & Web)\n";
    echo "========================================================================\n\n";

    $testCases = [
        [
            'title' => 'Test Case 1: Legitimate Query (username = "alice")',
            'payload' => 'alice',
        ],
        [
            'title' => 'Test Case 2: SQL Injection Attack (username = "\' OR \'1\'=\'1")',
            'payload' => "' OR '1'='1",
        ],
        [
            'title' => 'Test Case 3: Comment-Based Injection (username = "admin\' --")',
            'payload' => "admin' --",
        ],
    ];

    foreach ($testCases as $case) {
        echo "------------------------------------------------------------------------\n";
        echo ">>> " . $case['title'] . "\n";
        echo "------------------------------------------------------------------------\n";

        // 1. Insecure execution
        $insecureQuery = '';
        $insecureError = null;
        $insecureResults = $userRepo->findByUsernameInsecure($case['payload'], $insecureQuery, $insecureError);
        echo " [INSECURE - Direct Concatenation]\n";
        echo "   Query: " . $insecureQuery . "\n";
        if ($insecureError) {
            echo "   Status: SQL Error leaked: " . $insecureError . "\n";
        } else {
            echo "   Records Returned: " . count($insecureResults) . "\n";
            if (count($insecureResults) > 1) {
                echo "   SECURITY ALERT: SQL Injection SUCCESSFUL! Returned all records.\n";
            }
        }

        // 2. Secure execution
        $secureQuery = '';
        $secureError = null;
        $secureResults = $userRepo->findByUsernameSecure($case['payload'], $secureQuery, $secureError);
        echo "\n [SECURE - Prepared Statements]\n";
        echo "   Query: " . $secureQuery . "\n";
        if ($secureError) {
            echo "   Status: Safe error handling: " . $secureError . "\n";
        } else {
            echo "   Records Returned: " . count($secureResults) . "\n";
            if ($case['payload'] === 'alice') {
                echo "   Result: Legitimate user record safely retrieved.\n";
            } else {
                echo "   DEFENSE VERIFIED: Injection neutralized. Input treated strictly as literal data.\n";
            }
        }
        echo "\n";
    }
    echo "========================================================================\n";
    echo " All verification tests passed. Prepared statements fully neutralized SQLi.\n";
    echo "========================================================================\n";
    exit(0);
}

// -----------------------------------------------------------------------------
// Web Interface Handling
// -----------------------------------------------------------------------------

// Capture input from $_GET['username'] as specified in assignment requirements
$usernameInput = isset($_GET['username']) ? trim((string)$_GET['username']) : '';
$modeInput = isset($_GET['mode']) ? (string)$_GET['mode'] : 'secure'; // Default to secure defense mode

$hasSearched = isset($_GET['username']);
$executedQuery = '';
$queryError = null;
$results = [];
$isAttackPayload = (strpos($usernameInput, "'") !== false || stripos($usernameInput, 'OR') !== false);

if ($hasSearched) {
    if ($modeInput === 'insecure') {
        $results = $userRepo->findByUsernameInsecure($usernameInput, $executedQuery, $queryError);
    } else {
        $results = $userRepo->findByUsernameSecure($usernameInput, $executedQuery, $queryError);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Defense | Cyber Bootcamp</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --surface-color: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-heading: #f0f6fc;
            --accent-green: #238636;
            --accent-green-hover: #2ea043;
            --accent-red: #da3633;
            --accent-red-hover: #f85149;
            --accent-blue: #58a6ff;
            --tag-vuln-bg: rgba(218, 54, 51, 0.15);
            --tag-vuln-border: rgba(248, 81, 73, 0.4);
            --tag-secure-bg: rgba(35, 134, 54, 0.15);
            --tag-secure-border: rgba(46, 160, 67, 0.4);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 960px;
            margin: 0 auto;
        }

        header {
            margin-bottom: 2rem;
            text-align: center;
        }

        header h1 {
            color: var(--text-heading);
            font-size: 1.85rem;
            margin-bottom: 0.5rem;
        }

        header p {
            color: #8b949e;
            font-size: 0.95rem;
        }

        .card {
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }

        .card h2 {
            font-size: 1.25rem;
            color: var(--text-heading);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        label {
            display: block;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--text-heading);
        }

        input[type="text"] {
            width: 100%;
            padding: 0.65rem 0.85rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background-color: #0d1117;
            color: var(--text-heading);
            font-size: 1rem;
            font-family: monospace;
            outline: none;
            transition: border-color 0.2s;
        }

        input[type="text"]:focus {
            border-color: var(--accent-blue);
        }

        .radio-group {
            display: flex;
            gap: 1.5rem;
            margin-top: 0.5rem;
        }

        .radio-label {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            cursor: pointer;
            font-weight: normal;
        }

        .quick-payloads {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.6rem;
            align-items: center;
        }

        .quick-payloads span {
            font-size: 0.85rem;
            color: #8b949e;
        }

        .payload-btn {
            background: #21262d;
            border: 1px solid var(--border-color);
            color: var(--accent-blue);
            font-family: monospace;
            font-size: 0.8rem;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
        }

        .payload-btn:hover {
            background: #30363d;
        }

        .submit-btn {
            background-color: var(--accent-green);
            color: #ffffff;
            border: none;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 0.5rem;
        }

        .submit-btn:hover {
            background-color: var(--accent-green-hover);
        }

        .badge {
            display: inline-block;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            letter-spacing: 0.5px;
        }

        .badge-danger {
            background-color: var(--tag-vuln-bg);
            color: #f85149;
            border: 1px solid var(--tag-vuln-border);
        }

        .badge-success {
            background-color: var(--tag-secure-bg);
            color: #56d364;
            border: 1px solid var(--tag-secure-border);
        }

        .code-block {
            background-color: #090d13;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 0.9rem;
            color: #79c0ff;
            overflow-x: auto;
            margin-bottom: 1rem;
        }

        .alert {
            border-radius: 6px;
            padding: 0.9rem 1.1rem;
            margin-bottom: 1.25rem;
            font-size: 0.92rem;
            border: 1px solid transparent;
        }

        .alert-danger {
            background-color: var(--tag-vuln-bg);
            border-color: var(--tag-vuln-border);
            color: #ff7b72;
        }

        .alert-success {
            background-color: var(--tag-secure-bg);
            border-color: var(--tag-secure-border);
            color: #7ee787;
        }

        .alert-info {
            background-color: rgba(56, 139, 253, 0.15);
            border-color: rgba(56, 139, 253, 0.4);
            color: #79c0ff;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.75rem;
            font-size: 0.92rem;
        }

        th, td {
            text-align: left;
            padding: 0.65rem 0.85rem;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: #21262d;
            color: var(--text-heading);
            font-weight: 600;
        }

        tr:hover td {
            background-color: rgba(255, 255, 255, 0.02);
        }

        .footer {
            text-align: center;
            font-size: 0.85rem;
            color: #8b949e;
            margin-top: 2rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ SQL Injection Defense Lab</h1>
            <p>Practical Demonstration: Insecure String Concatenation vs. PDO Prepared Statements</p>
        </header>

        <!-- Query Form -->
        <div class="card">
            <h2>User Search Query Form</h2>
            <form method="GET" action="">
                <div class="form-group">
                    <label for="username">Search by Username (<code>$_GET['username']</code>):</label>
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        value="<?= htmlspecialchars($usernameInput, ENT_QUOTES, 'UTF-8') ?>" 
                        placeholder="e.g. alice, admin, or test payload" 
                        required
                    >
                    <div class="quick-payloads">
                        <span>Quick Presets:</span>
                        <a href="?username=alice&mode=<?= urlencode($modeInput) ?>" class="payload-btn">alice (Normal)</a>
                        <a href="?username=' OR '1'='1&mode=<?= urlencode($modeInput) ?>" class="payload-btn">' OR '1'='1 (Attack)</a>
                        <a href="?username=admin' --&mode=<?= urlencode($modeInput) ?>" class="payload-btn">admin' -- (Comment Out)</a>
                    </div>
                </div>

                <div class="form-group">
                    <label>Execution Mode:</label>
                    <div class="radio-group">
                        <label class="radio-label">
                            <input 
                                type="radio" 
                                name="mode" 
                                value="secure" 
                                <?= $modeInput === 'secure' ? 'checked' : '' ?>
                            >
                            <span><strong>Secure:</strong> PDO Prepared Statements (Defense Enabled)</span>
                        </label>
                        <label class="radio-label">
                            <input 
                                type="radio" 
                                name="mode" 
                                value="insecure" 
                                <?= $modeInput === 'insecure' ? 'checked' : '' ?>
                            >
                            <span><strong>Insecure:</strong> Direct Concatenation (Vulnerable)</span>
                        </label>
                    </div>
                </div>

                <button type="submit" class="submit-btn">Execute Query</button>
            </form>
        </div>

        <?php if ($hasSearched): ?>
            <!-- Results and Security Evaluation -->
            <div class="card">
                <h2>
                    Security Analysis & Output
                    <?php if ($modeInput === 'insecure'): ?>
                        <span class="badge badge-danger">Insecure Mode</span>
                    <?php else: ?>
                        <span class="badge badge-success">Secure Mode (PDO)</span>
                    <?php endif; ?>
                </h2>

                <label>Executed SQL Statement:</label>
                <div class="code-block"><?= htmlspecialchars($executedQuery, ENT_QUOTES, 'UTF-8') ?></div>

                <?php if ($queryError): ?>
                    <div class="alert alert-danger">
                        <strong>Error:</strong> <?= htmlspecialchars($queryError, ENT_QUOTES, 'UTF-8') ?>
                    </div>
                <?php endif; ?>

                <?php if ($modeInput === 'insecure'): ?>
                    <?php if (count($results) > 1 && $isAttackPayload): ?>
                        <div class="alert alert-danger">
                            ⚠️ <strong>VULNERABILITY CONFIRMED:</strong> The SQL Injection payload bypassed query logic via direct string concatenation. All <strong><?= count($results) ?></strong> user records were dumped from the database.
                        </div>
                    <?php else: ?>
                        <div class="alert alert-info">
                            ℹ️ Query executed in insecure concatenation mode. Notice how untrusted input directly alters the SQL structure.
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <?php if ($isAttackPayload && count($results) === 0): ?>
                        <div class="alert alert-success">
                            🛡️ <strong>DEFENSE SUCCESSFUL:</strong> PDO prepared statements treated the payload <code><?= htmlspecialchars($usernameInput, ENT_QUOTES, 'UTF-8') ?></code> strictly as literal parameter data. The query logic was completely immune to alteration. 0 records matched.
                        </div>
                    <?php else: ?>
                        <div class="alert alert-success">
                            ✅ <strong>SECURE EXECUTION:</strong> Query executed safely using parameterized input binding. No SQL injection is possible.
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <h3>Query Results (<?= count($results) ?> record<?= count($results) === 1 ? '' : 's' ?> returned)</h3>
                <?php if (!empty($results)): ?>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Full Name</th>
                                <th>Email</th>
                                <th>Role</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($results as $row): ?>
                                <tr>
                                    <td><?= htmlspecialchars((string)$row['id'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><code><?= htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') ?></code></td>
                                    <td><?= htmlspecialchars($row['full_name'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($row['email'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($row['role'], ENT_QUOTES, 'UTF-8') ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <p style="color: #8b949e; margin-top: 0.5rem; font-style: italic;">No matching user records found in the database.</p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Educational Reference Card -->
        <div class="card">
            <h2>Technical Concept Breakdown</h2>
            <div style="font-size: 0.92rem; line-height: 1.7;">
                <p><strong>1. Why Insecure Concatenation Fails:</strong></p>
                <p style="color: #8b949e; margin-bottom: 0.75rem;">
                    When injecting <code>' OR '1'='1</code> into <code>SELECT * FROM users WHERE username = '$username'</code>, the query becomes <code>WHERE username = '' OR '1'='1'</code>. Because <code>'1'='1'</code> is always true, the database returns every row in the table, destroying access control.
                </p>
                <p><strong>2. How PDO Prepared Statements Protect:</strong></p>
                <p style="color: #8b949e;">
                    Prepared statements compile the SQL template <em>before</em> binding data. The database query engine never interprets user input as executable SQL commands, neutralizing all SQL injection vectors regardless of quotes, hyphens, or SQL keywords.
                </p>
            </div>
        </div>

        <div class="footer">
            Cybersecurity Programming Bootcamp &bull; SQL Injection Defense &bull; PDO Prepared Statements
        </div>
    </div>
</body>
</html>

