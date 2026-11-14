<?php
/**
 * ============================================================================
 * Cyber Bootcamp - Assignment 10: HTTP Request Handler & REST API Tool
 * (التكليف العاشر: أداة معالجة طلبات HTTP وبناء REST API)
 * Track: Cybersecurity Programming (PHP & Web)
 *
 * Objectives:
 * 1. Set standard REST API response headers (Content-Type: application/json).
 * 2. Detect and inspect incoming HTTP methods via $_SERVER['REQUEST_METHOD'].
 * 3. Extract and parse raw JSON request bodies via php://input and json_decode().
 * 4. Inspect incoming HTTP headers using getallheaders() and track security
 *    headers such as 'Authorization'.
 * 5. Route requests using a structured conditional mechanism (switch/case)
 *    supporting GET, POST, PUT, and DELETE with strict status code adherence.
 * 6. Return structured, sanitized JSON responses with defensive error handling
 *    (e.g., 200 OK, 201 Created, 400 Bad Request, 405 Method Not Allowed).
 * ============================================================================
 */

// Defensive polyfill for getallheaders() across non-Apache/CLI SAPI environments
if (!function_exists('getallheaders')) {
    function getallheaders(): array {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                // Convert HTTP_HEADER_NAME to Header-Name format
                $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$headerName] = $value;
            } elseif ($key === 'CONTENT_TYPE') {
                $headers['Content-Type'] = $value;
            } elseif ($key === 'CONTENT_LENGTH') {
                $headers['Content-Length'] = $value;
            }
        }
        return $headers;
    }
}

// ----------------------------------------------------------------------------
// Step 1: Enforce API Output Header
// ----------------------------------------------------------------------------
// Configure the HTTP response header to serve JSON with UTF-8 character encoding.
// Also add security headers to prevent MIME-sniffing and cross-site framing.
header("Content-Type: application/json; charset=UTF-8");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

// ----------------------------------------------------------------------------
// Step 2: Read HTTP Request Method
// ----------------------------------------------------------------------------
// Retrieve the HTTP request verb (GET, POST, PUT, DELETE, etc.)
// Default to 'GET' if running in CLI or if the server variable is unset.
$requestMethod = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

// ----------------------------------------------------------------------------
// Step 3: Inspect Request Headers & Security Tokens
// ----------------------------------------------------------------------------
// Use getallheaders() to read incoming HTTP headers and examine security headers.
$headers = getallheaders();

// Search for the Authorization header in a case-insensitive manner
$authHeader = null;
foreach ($headers as $headerName => $headerValue) {
    if (strcasecmp($headerName, 'Authorization') === 0) {
        $authHeader = $headerValue;
        break;
    }
}

// Prepare header security audit metadata for the response
$securityAudit = [
    'auth_header_present' => !empty($authHeader),
    'auth_header_type'    => $authHeader ? (explode(' ', trim($authHeader))[0] ?? 'Unknown') : 'None',
    'client_ip'           => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
    'user_agent'          => $headers['User-Agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
    'content_type'        => $headers['Content-Type'] ?? ($_SERVER['CONTENT_TYPE'] ?? 'Not Specified')
];

// ----------------------------------------------------------------------------
// Step 4: Extract and Parse Request Body Payload (JSON)
// ----------------------------------------------------------------------------
// Read raw stream data from the php://input read-only stream.
$rawBody = file_get_contents('php://input');
$parsedBody = null;

if (!empty($rawBody)) {
    // Decode JSON string into an associative PHP array
    $parsedBody = json_decode($rawBody, true);

    // Validate JSON syntax; return 400 Bad Request on decoding failure
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode([
            'status'     => 'error',
            'code'       => 400,
            'error'      => 'Bad Request: Malformed JSON payload.',
            'json_error' => json_last_error_msg()
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        exit;
    }
}

// ----------------------------------------------------------------------------
// Step 5: Mock In-Memory Data Store (Bootcamp Security Context)
// ----------------------------------------------------------------------------
// Simulated target assets/endpoints for demonstration purposes
$mockTargets = [
    1 => ['id' => 1, 'hostname' => 'gateway.corp.local', 'ip' => '192.168.1.1', 'status' => 'active'],
    2 => ['id' => 2, 'hostname' => 'auth.corp.local',    'ip' => '192.168.1.10', 'status' => 'active'],
    3 => ['id' => 3, 'hostname' => 'db.corp.local',      'ip' => '192.168.1.20', 'status' => 'restricted']
];

// ----------------------------------------------------------------------------
// Step 6: Method Routing & Business Logic Execution
// ----------------------------------------------------------------------------
$response = [];

switch ($requestMethod) {

    // ------------------------------------------------------------------------
    // GET: Retrieve resources or inspect system status
    // ------------------------------------------------------------------------
    case 'GET':
        http_response_code(200);

        // Check if a specific resource ID was requested via query parameter ?id=
        $targetId = isset($_GET['id']) ? (int)$_GET['id'] : null;

        if ($targetId !== null) {
            if (isset($mockTargets[$targetId])) {
                $response = [
                    'status'         => 'success',
                    'code'           => 200,
                    'message'        => "Resource with ID {$targetId} retrieved successfully.",
                    'data'           => $mockTargets[$targetId],
                    'security_audit' => $securityAudit
                ];
            } else {
                http_response_code(404);
                $response = [
                    'status'         => 'error',
                    'code'           => 404,
                    'message'        => "Resource with ID {$targetId} not found.",
                    'security_audit' => $securityAudit
                ];
            }
        } else {
            // Return full collection
            $response = [
                'status'         => 'success',
                'code'           => 200,
                'message'        => 'Resource collection retrieved successfully.',
                'count'          => count($mockTargets),
                'data'           => array_values($mockTargets),
                'security_audit' => $securityAudit
            ];
        }
        break;

    // ------------------------------------------------------------------------
    // POST: Create a new resource using input JSON data
    // ------------------------------------------------------------------------
    case 'POST':
        // Ensure payload is provided
        if (empty($parsedBody)) {
            http_response_code(400);
            $response = [
                'status'  => 'error',
                'code'    => 400,
                'message' => 'Bad Request: Missing JSON body in POST request.'
            ];
            break;
        }

        // Validate mandatory fields
        if (empty($parsedBody['hostname']) || empty($parsedBody['ip'])) {
            http_response_code(422); // Unprocessable Entity
            $response = [
                'status'  => 'error',
                'code'    => 422,
                'message' => 'Validation Error: Required fields "hostname" and "ip" must be provided.',
                'received_fields' => array_keys($parsedBody)
            ];
            break;
        }

        // Simulate record creation
        $newId = count($mockTargets) + 1;
        $createdResource = [
            'id'         => $newId,
            'hostname'   => htmlspecialchars((string)$parsedBody['hostname'], ENT_QUOTES, 'UTF-8'),
            'ip'         => filter_var($parsedBody['ip'], FILTER_VALIDATE_IP) ?: 'Invalid IP',
            'status'     => htmlspecialchars((string)($parsedBody['status'] ?? 'pending'), ENT_QUOTES, 'UTF-8'),
            'created_at' => date('Y-m-d H:i:s')
        ];

        http_response_code(201); // 201 Created
        $response = [
            'status'         => 'success',
            'code'           => 201,
            'message'        => 'Resource created successfully.',
            'data'           => $createdResource,
            'security_audit' => $securityAudit
        ];
        break;

    // ------------------------------------------------------------------------
    // PUT: Update an existing resource using JSON payload
    // ------------------------------------------------------------------------
    case 'PUT':
        if (empty($parsedBody)) {
            http_response_code(400);
            $response = [
                'status'  => 'error',
                'code'    => 400,
                'message' => 'Bad Request: Missing JSON body in PUT request.'
            ];
            break;
        }

        // Determine target ID from query parameter or JSON payload
        $targetId = isset($_GET['id']) ? (int)$_GET['id'] : (isset($parsedBody['id']) ? (int)$parsedBody['id'] : null);

        if ($targetId === null) {
            http_response_code(400);
            $response = [
                'status'  => 'error',
                'code'    => 400,
                'message' => 'Bad Request: Target resource "id" must be specified via URL query or JSON body.'
            ];
            break;
        }

        // Simulate resource update
        http_response_code(200);
        $updatedData = [
            'id'         => $targetId,
            'hostname'   => htmlspecialchars((string)($parsedBody['hostname'] ?? 'updated-host.corp.local'), ENT_QUOTES, 'UTF-8'),
            'ip'         => htmlspecialchars((string)($parsedBody['ip'] ?? '192.168.1.100'), ENT_QUOTES, 'UTF-8'),
            'status'     => htmlspecialchars((string)($parsedBody['status'] ?? 'modified'), ENT_QUOTES, 'UTF-8'),
            'updated_at' => date('Y-m-d H:i:s')
        ];

        $response = [
            'status'         => 'success',
            'code'           => 200,
            'message'        => "Resource with ID {$targetId} updated successfully.",
            'data'           => $updatedData,
            'security_audit' => $securityAudit
        ];
        break;

    // ------------------------------------------------------------------------
    // DELETE: Remove a resource
    // ------------------------------------------------------------------------
    case 'DELETE':
        // Determine target ID from query string or body
        $targetId = isset($_GET['id']) ? (int)$_GET['id'] : (isset($parsedBody['id']) ? (int)$parsedBody['id'] : null);

        if ($targetId === null) {
            http_response_code(400);
            $response = [
                'status'  => 'error',
                'code'    => 400,
                'message' => 'Bad Request: Target resource "id" must be specified to execute DELETE.'
            ];
            break;
        }

        http_response_code(200);
        $response = [
            'status'         => 'success',
            'code'           => 200,
            'message'        => "Resource with ID {$targetId} deleted successfully.",
            'deleted_id'     => $targetId,
            'security_audit' => $securityAudit
        ];
        break;

    // ------------------------------------------------------------------------
    // Default: Reject unsupported HTTP methods
    // ------------------------------------------------------------------------
    default:
        // Announce supported HTTP verbs in the 'Allow' response header
        header("Allow: GET, POST, PUT, DELETE");
        http_response_code(405); // 405 Method Not Allowed

        $response = [
            'status'            => 'error',
            'code'              => 405,
            'message'           => "Method '{$requestMethod}' is not allowed on this endpoint.",
            'supported_methods' => ['GET', 'POST', 'PUT', 'DELETE'],
            'security_audit'    => $securityAudit
        ];
        break;
}

// ----------------------------------------------------------------------------
// Step 7: Output Formatted JSON Response
// ----------------------------------------------------------------------------
// Encode the response array into human-readable, formatted JSON.
echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;

