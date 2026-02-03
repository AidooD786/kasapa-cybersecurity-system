<?php
// Kasapa FM Cybersecurity Database Configuration
// config.php

class Database {
    private $host = "localhost";
    private $db_name = "kasapa_cybersecurity";
    private $username = "kasapa_admin";
    private $password = "SecurePassword123!";
    private $conn;
    
    public function getConnection() {
        $this->conn = null;
        
        try {
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->db_name,
                $this->username,
                $this->password
            );
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->conn->exec("set names utf8");
        } catch(PDOException $exception) {
            error_log("Connection error: " . $exception->getMessage());
            return null;
        }
        
        return $this->conn;
    }
    
    public function validateUser($email, $password) {
        $conn = $this->getConnection();
        
        if (!$conn) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        try {
            $query = "SELECT id, first_name, last_name, email, password_hash, role, 
                             department, account_locked, failed_attempts
                      FROM users 
                      WHERE email = :email";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(":email", $email);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Check if account is locked
                if ($row['account_locked']) {
                    return [
                        'success' => false,
                        'message' => 'Account locked due to too many failed attempts'
                    ];
                }
                
                // Verify password
                if (password_verify($password, $row['password_hash'])) {
                    // Reset failed attempts on successful login
                    $this->resetFailedAttempts($row['id']);
                    
                    // Update last login
                    $this->updateLastLogin($row['id']);
                    
                    // Log successful access
                    $this->logAccess($row['id'], 'LOGIN', 'success');
                    
                    return [
                        'success' => true,
                        'user' => [
                            'id' => $row['id'],
                            'name' => $row['first_name'] . ' ' . $row['last_name'],
                            'email' => $row['email'],
                            'role' => $row['role'],
                            'department' => $row['department']
                        ]
                    ];
                } else {
                    // Increment failed attempts
                    $failed_attempts = $this->incrementFailedAttempts($row['id']);
                    
                    // Log failed access
                    $this->logAccess($row['id'], 'LOGIN', 'failed');
                    
                    // Lock account after 5 failed attempts
                    if ($failed_attempts >= 5) {
                        $this->lockAccount($row['id']);
                        return [
                            'success' => false,
                            'message' => 'Account locked due to too many failed attempts'
                        ];
                    }
                    
                    return [
                        'success' => false,
                        'message' => 'Invalid credentials',
                        'attempts_remaining' => 5 - $failed_attempts
                    ];
                }
            } else {
                return ['success' => false, 'message' => 'User not found'];
            }
        } catch(PDOException $exception) {
            error_log("Login error: " . $exception->getMessage());
            return ['success' => false, 'message' => 'Authentication error'];
        }
    }
    
    private function incrementFailedAttempts($user_id) {
        $conn = $this->getConnection();
        $query = "UPDATE users 
                  SET failed_attempts = failed_attempts + 1,
                      updated_at = NOW()
                  WHERE id = :user_id";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();
        
        // Get current count
        $query = "SELECT failed_attempts FROM users WHERE id = :user_id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();
        
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row['failed_attempts'];
    }
    
    private function resetFailedAttempts($user_id) {
        $conn = $this->getConnection();
        $query = "UPDATE users 
                  SET failed_attempts = 0,
                      account_locked = FALSE,
                      updated_at = NOW()
                  WHERE id = :user_id";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();
    }
    
    private function lockAccount($user_id) {
        $conn = $this->getConnection();
        $query = "UPDATE users 
                  SET account_locked = TRUE,
                      updated_at = NOW()
                  WHERE id = :user_id";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();
    }
    
    private function updateLastLogin($user_id) {
        $conn = $this->getConnection();
        $query = "UPDATE users 
                  SET last_login = NOW(),
                      updated_at = NOW()
                  WHERE id = :user_id";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();
    }
    
    private function logAccess($user_id, $action, $status) {
        $conn = $this->getConnection();
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $query = "INSERT INTO access_logs 
                  (user_id, ip_address, user_agent, action, status, timestamp)
                  VALUES (:user_id, :ip_address, :user_agent, :action, :status, NOW())";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":status", $status);
        $stmt->execute();
    }
    
    public function registerUser($user_data) {
        $conn = $this->getConnection();
        
        if (!$conn) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        try {
            // Generate employee ID
            $employee_id = $this->generateEmployeeId($user_data['department']);
            
            // Hash password
            $password_hash = password_hash($user_data['password'], PASSWORD_DEFAULT);
            
            $query = "INSERT INTO users 
                      (employee_id, first_name, last_name, email, password_hash, 
                       department, role, created_at)
                      VALUES (:employee_id, :first_name, :last_name, :email, 
                              :password_hash, :department, :role, NOW())";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(":employee_id", $employee_id);
            $stmt->bindParam(":first_name", $user_data['first_name']);
            $stmt->bindParam(":last_name", $user_data['last_name']);
            $stmt->bindParam(":email", $user_data['email']);
            $stmt->bindParam(":password_hash", $password_hash);
            $stmt->bindParam(":department", $user_data['department']);
            $stmt->bindParam(":role", $user_data['role']);
            
            if ($stmt->execute()) {
                $user_id = $conn->lastInsertId();
                
                // Log the registration
                $this->logAccess($user_id, 'REGISTRATION', 'success');
                
                return [
                    'success' => true,
                    'message' => 'User registered successfully',
                    'employee_id' => $employee_id
                ];
            } else {
                return ['success' => false, 'message' => 'Registration failed'];
            }
        } catch(PDOException $exception) {
            if ($exception->getCode() == 23000) { // Duplicate entry
                return ['success' => false, 'message' => 'Email already exists'];
            }
            error_log("Registration error: " . $exception->getMessage());
            return ['success' => false, 'message' => 'Registration error'];
        }
    }
    
    private function generateEmployeeId($department) {
        $prefix = 'KFM-';
        
        switch($department) {
            case 'it': $prefix .= 'IT-'; break;
            case 'newsroom': $prefix .= 'NEWS-'; break;
            case 'studio': $prefix .= 'STUDIO-'; break;
            case 'admin': $prefix .= 'ADMIN-'; break;
            case 'security': $prefix .= 'SEC-'; break;
            default: $prefix .= 'EMP-';
        }
        
        $conn = $this->getConnection();
        $query = "SELECT COUNT(*) as count FROM users WHERE department = :department";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(":department", $department);
        $stmt->execute();
        
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $count = $row['count'] + 1;
        
        return $prefix . str_pad($count, 3, '0', STR_PAD_LEFT);
    }
    
    public function getDashboardStats() {
        $conn = $this->getConnection();
        
        if (!$conn) {
            return null;
        }
        
        try {
            $query = "SELECT * FROM dashboard_stats";
            $stmt = $conn->prepare($query);
            $stmt->execute();
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch(PDOException $exception) {
            error_log("Dashboard stats error: " . $exception->getMessage());
            return null;
        }
    }
    
    public function getRecentIncidents($limit = 10) {
        $conn = $this->getConnection();
        
        if (!$conn) {
            return [];
        }
        
        try {
            $query = "SELECT i.*, CONCAT(u.first_name, ' ', u.last_name) as reporter_name
                      FROM incidents i
                      JOIN users u ON i.reporter_id = u.id
                      ORDER BY i.reported_at DESC
                      LIMIT :limit";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch(PDOException $exception) {
            error_log("Recent incidents error: " . $exception->getMessage());
            return [];
        }
    }
    
    public function createIncident($incident_data) {
        $conn = $this->getConnection();
        
        if (!$conn) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        try {
            // Call stored procedure
            $query = "CALL ReportIncident(:title, :description, :category, 
                      :severity, :reporter_id, :broadcast_affected)";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(":title", $incident_data['title']);
            $stmt->bindParam(":description", $incident_data['description']);
            $stmt->bindParam(":category", $incident_data['category']);
            $stmt->bindParam(":severity", $incident_data['severity']);
            $stmt->bindParam(":reporter_id", $incident_data['reporter_id']);
            $stmt->bindParam(":broadcast_affected", $incident_data['broadcast_affected']);
            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return [
                'success' => true,
                'message' => 'Incident reported successfully',
                'incident_id' => $result['incident_id']
            ];
        } catch(PDOException $exception) {
            error_log("Incident creation error: " . $exception->getMessage());
            return ['success' => false, 'message' => 'Incident reporting failed'];
        }
    }
}

// Initialize session and security headers
session_start();

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// CORS headers for API access
if (isset($_SERVER['HTTP_ORIGIN'])) {
    $allowed_origins = ['https://kasapafm.com', 'https://cybersecurity.kasapafm.com'];
    if (in_array($_SERVER['HTTP_ORIGIN'], $allowed_origins)) {
        header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
    }
}

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// CSRF Token Generation
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    return true;
}

// API Response Helper
function jsonResponse($data, $status_code = 200) {
    http_response_code($status_code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit();
}

// Authentication Middleware
function requireAuth($required_role = null) {
    if (!isset($_SESSION['user'])) {
        jsonResponse(['error' => 'Authentication required'], 401);
    }
    
    if ($required_role && $_SESSION['user']['role'] !== $required_role) {
        jsonResponse(['error' => 'Insufficient permissions'], 403);
    }
    
    return $_SESSION['user'];
}

// Input Validation
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    
    $input = trim($input);
    $input = stripslashes($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    
    return $input;
}

// API Endpoints Handler
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action'])) {
    $action = $_GET['action'];
    $db = new Database();
    
    switch ($action) {
        case 'login':
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data || !isset($data['email']) || !isset($data['password'])) {
                jsonResponse(['success' => false, 'message' => 'Invalid request'], 400);
            }
            
            $result = $db->validateUser(
                sanitizeInput($data['email']),
                $data['password'] // Password not sanitized for hashing
            );
            
            if ($result['success']) {
                $_SESSION['user'] = $result['user'];
                $_SESSION['last_activity'] = time();
                
                // Regenerate session ID for security
                session_regenerate_id(true);
                
                jsonResponse([
                    'success' => true,
                    'user' => $result['user'],
                    'redirect' => $result['user']['role'] === 'admin' ? 'admin.html' : 'dashboard.html'
                ]);
            } else {
                jsonResponse($result, 401);
            }
            break;
            
        case 'logout':
            session_destroy();
            jsonResponse(['success' => true, 'message' => 'Logged out successfully']);
            break;
            
        case 'register':
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data || !isset($data['email']) || !isset($data['password'])) {
                jsonResponse(['success' => false, 'message' => 'Invalid request'], 400);
            }
            
            // Validate CSRF token for registration
            if (!isset($data['csrf_token']) || !validateCsrfToken($data['csrf_token'])) {
                jsonResponse(['success' => false, 'message' => 'Invalid CSRF token'], 403);
            }
            
            $result = $db->registerUser([
                'first_name' => sanitizeInput($data['first_name'] ?? ''),
                'last_name' => sanitizeInput($data['last_name'] ?? ''),
                'email' => sanitizeInput($data['email']),
                'password' => $data['password'],
                'department' => sanitizeInput($data['department'] ?? 'it'),
                'role' => sanitizeInput($data['role'] ?? 'viewer')
            ]);
            
            jsonResponse($result, $result['success'] ? 201 : 400);
            break;
            
        case 'report_incident':
            $user = requireAuth();
            
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data || !isset($data['title']) || !isset($data['category'])) {
                jsonResponse(['success' => false, 'message' => 'Invalid request'], 400);
            }
            
            $result = $db->createIncident([
                'title' => sanitizeInput($data['title']),
                'description' => sanitizeInput($data['description'] ?? ''),
                'category' => sanitizeInput($data['category']),
                'severity' => sanitizeInput($data['severity'] ?? 'medium'),
                'reporter_id' => $user['id'],
                'broadcast_affected' => (bool)($data['broadcast_affected'] ?? false)
            ]);
            
            jsonResponse($result, $result['success'] ? 201 : 400);
            break;
            
        case 'dashboard_stats':
            $user = requireAuth();
            $stats = $db->getDashboardStats();
            
            if ($stats) {
                jsonResponse(['success' => true, 'stats' => $stats]);
            } else {
                jsonResponse(['success' => false, 'message' => 'Unable to fetch stats'], 500);
            }
            break;
            
        default:
            jsonResponse(['success' => false, 'message' => 'Invalid action'], 404);
    }
}
?>