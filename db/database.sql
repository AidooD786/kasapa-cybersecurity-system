-- Kasapa FM Cybersecurity Database Schema
-- MySQL Database Structure

CREATE DATABASE IF NOT EXISTS kasapa_cybersecurity;
USE kasapa_cybersecurity;

-- Users Table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    employee_id VARCHAR(20) UNIQUE,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    department ENUM('it', 'newsroom', 'studio', 'admin', 'security') NOT NULL,
    role ENUM('admin', 'technician', 'journalist', 'analyst', 'viewer') NOT NULL,
    mfa_secret VARCHAR(32),
    last_login DATETIME,
    failed_attempts INT DEFAULT 0,
    account_locked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_department (department),
    INDEX idx_role (role)
);

-- Access Logs Table
CREATE TABLE access_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(100),
    status ENUM('success', 'failed') NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action)
);

-- Cybersecurity Incidents Table
CREATE TABLE incidents (
    id INT PRIMARY KEY AUTO_INCREMENT,
    incident_id VARCHAR(20) UNIQUE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    category ENUM('ransomware', 'phishing', 'ddos', 'hijacking', 'malware', 'data_breach', 'physical', 'other') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('reported', 'investigating', 'contained', 'resolved', 'closed') DEFAULT 'reported',
    reporter_id INT NOT NULL,
    assigned_to INT,
    broadcast_affected BOOLEAN DEFAULT FALSE,
    downtime_minutes INT DEFAULT 0,
    data_loss BOOLEAN DEFAULT FALSE,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (reporter_id) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_category (category),
    INDEX idx_reported_at (reported_at)
);

-- Incident Timeline Table
CREATE TABLE incident_timeline (
    id INT PRIMARY KEY AUTO_INCREMENT,
    incident_id INT NOT NULL,
    user_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_incident_id (incident_id),
    INDEX idx_timestamp (timestamp)
);

-- Network Devices Table
CREATE TABLE network_devices (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id VARCHAR(50) UNIQUE,
    name VARCHAR(100) NOT NULL,
    type ENUM('firewall', 'router', 'switch', 'server', 'workstation', 'iot') NOT NULL,
    ip_address VARCHAR(45),
    mac_address VARCHAR(17),
    vlan VARCHAR(20),
    location ENUM('studio', 'newsroom', 'admin', 'server_room', 'field') NOT NULL,
    os_version VARCHAR(50),
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status ENUM('online', 'offline', 'maintenance') DEFAULT 'online',
    vulnerabilities JSON,
    INDEX idx_location (location),
    INDEX idx_status (status),
    INDEX idx_type (type)
);

-- Security Alerts Table
CREATE TABLE security_alerts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    alert_id VARCHAR(20) UNIQUE,
    device_id INT,
    type ENUM('intrusion', 'malware', 'unauthorized_access', 'dos', 'configuration', 'compliance') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    rule_triggered VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INT,
    acknowledged_at DATETIME,
    FOREIGN KEY (device_id) REFERENCES network_devices(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id),
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp),
    INDEX idx_type (type),
    INDEX idx_acknowledged (acknowledged)
);

-- Backup Logs Table
CREATE TABLE backup_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    backup_id VARCHAR(30) UNIQUE,
    type ENUM('full', 'incremental', 'differential') NOT NULL,
    target ENUM('audio_files', 'database', 'configurations', 'user_data') NOT NULL,
    location ENUM('local', 'cloud', 'offsite') NOT NULL,
    size_mb DECIMAL(10,2),
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    status ENUM('success', 'failed', 'partial') NOT NULL,
    error_message TEXT,
    verified BOOLEAN DEFAULT FALSE,
    retention_days INT,
    INDEX idx_target (target),
    INDEX idx_status (status),
    INDEX idx_start_time (start_time)
);

-- Training Records Table
CREATE TABLE training_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    module ENUM('phishing', 'password_security', 'social_engineering', 'incident_reporting', 'data_protection') NOT NULL,
    completion_date DATE NOT NULL,
    score DECIMAL(5,2),
    expires_date DATE,
    certificate_path VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_module (module),
    INDEX idx_completion_date (completion_date)
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action_type VARCHAR(50) NOT NULL,
    table_name VARCHAR(50),
    record_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action_type (action_type),
    INDEX idx_timestamp (timestamp)
);

-- Insert Default Admin User
INSERT INTO users (
    employee_id, 
    first_name, 
    last_name, 
    email, 
    password_hash, 
    department, 
    role
) VALUES (
    'KFM-ADMIN-001',
    'System',
    'Administrator',
    'admin@kasapafm.com',
    '$2y$10$YourHashedPasswordHere', -- Use password_hash() in PHP
    'it',
    'admin'
);

-- Insert Default Technician
INSERT INTO users (
    employee_id,
    first_name,
    last_name,
    email,
    password_hash,
    department,
    role
) VALUES (
    'KFM-TECH-001',
    'Broadcast',
    'Technician',
    'tech@kasapafm.com',
    '$2y$10$YourHashedPasswordHere',
    'studio',
    'technician'
);

-- Create Views for Reporting
CREATE VIEW dashboard_stats AS
SELECT 
    (SELECT COUNT(*) FROM users WHERE role != 'admin') as total_staff,
    (SELECT COUNT(*) FROM incidents WHERE status != 'closed') as active_incidents,
    (SELECT COUNT(*) FROM security_alerts WHERE acknowledged = FALSE) as pending_alerts,
    (SELECT COUNT(*) FROM network_devices WHERE status = 'online') as online_devices;

CREATE VIEW incident_report AS
SELECT 
    i.incident_id,
    i.title,
    i.category,
    i.severity,
    i.status,
    CONCAT(u.first_name, ' ', u.last_name) as reporter,
    i.reported_at,
    i.downtime_minutes
FROM incidents i
JOIN users u ON i.reporter_id = u.id;

-- Create Stored Procedures
DELIMITER //

CREATE PROCEDURE ReportIncident(
    IN p_title VARCHAR(200),
    IN p_description TEXT,
    IN p_category VARCHAR(50),
    IN p_severity VARCHAR(20),
    IN p_reporter_id INT,
    IN p_broadcast_affected BOOLEAN
)
BEGIN
    DECLARE new_incident_id VARCHAR(20);
    
    -- Generate incident ID
    SET new_incident_id = CONCAT('INC-', DATE_FORMAT(NOW(), '%Y%m%d-'), LPAD(FLOOR(RAND() * 10000), 4, '0'));
    
    INSERT INTO incidents (
        incident_id,
        title,
        description,
        category,
        severity,
        reporter_id,
        broadcast_affected,
        reported_at
    ) VALUES (
        new_incident_id,
        p_title,
        p_description,
        p_category,
        p_severity,
        p_reporter_id,
        p_broadcast_affected,
        NOW()
    );
    
    SELECT new_incident_id as incident_id;
END //

CREATE PROCEDURE GetUserActivity(
    IN p_user_id INT,
    IN p_days INT
)
BEGIN
    SELECT 
        al.action,
        al.resource,
        al.status,
        al.timestamp,
        al.ip_address
    FROM access_logs al
    WHERE al.user_id = p_user_id
    AND al.timestamp >= DATE_SUB(NOW(), INTERVAL p_days DAY)
    ORDER BY al.timestamp DESC
    LIMIT 100;
END //

DELIMITER ;

-- Create Triggers
DELIMITER //

CREATE TRIGGER after_user_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (user_id, action_type, table_name, record_id, new_values)
    VALUES (NEW.id, 'INSERT', 'users', NEW.id, JSON_OBJECT(
        'email', NEW.email,
        'role', NEW.role,
        'department', NEW.department
    ));
END //

CREATE TRIGGER after_incident_update
AFTER UPDATE ON incidents
FOR EACH ROW
BEGIN
    IF OLD.status != NEW.status THEN
        INSERT INTO incident_timeline (incident_id, user_id, action, description)
        VALUES (NEW.id, NEW.assigned_to, 'STATUS_CHANGE', 
                CONCAT('Status changed from ', OLD.status, ' to ', NEW.status));
    END IF;
END //

DELIMITER ;