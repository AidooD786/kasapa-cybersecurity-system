const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/report-incident', (req, res) => {
    res.sendFile(path.join(__dirname, 'report-incident.html'));
});

// Mock database (for testing without MySQL)
const mockDB = {
  users: [
    {
      id: 1,
      email: 'admin@kasapafm.com',
      password: '$2a$10$N9qo8uLOickgx2ZMRZoMye',
      name: 'System Administrator',
      role: 'admin',
      department: 'it'
    },
    {
      id: 2,
      email: 'tech@kasapafm.com',
      password: '$2a$10$N9qo8uLOickgx2ZMRZoMye',
      name: 'Broadcast Technician',
      role: 'technician',
      department: 'studio'
    },
    {
      id: 3,
      email: 'journalist@kasapafm.com',
      password: '$2a$10$N9qo8uLOickgx2ZMRZoMye',
      name: 'News Reporter',
      role: 'journalist',
      department: 'newsroom'
    }
  ],
  incidents: [
    {
      id: 'INC-2024001',
      title: 'Phishing Attempt Detected',
      category: 'phishing',
      severity: 'medium',
      status: 'investigating',
      reported_by: 'System Administrator',
      reported_at: '2024-01-15 10:30:00'
    },
    {
      id: 'INC-2024002',
      title: 'Unusual Network Activity',
      category: 'unauthorized_access',
      severity: 'high',
      status: 'contained',
      reported_by: 'Broadcast Technician',
      reported_at: '2024-01-14 15:45:00'
    }
  ],
  devices: [
    { id: 1, name: 'Main Broadcast Server', status: 'online', type: 'server' },
    { id: 2, name: 'Newsroom Switch', status: 'online', type: 'network' },
    { id: 3, name: 'Studio Workstation', status: 'offline', type: 'workstation' }
  ],
  alerts: [
    { id: 1, type: 'Intrusion Attempt', severity: 'high', status: 'active', timestamp: '2024-01-15 09:15:00' },
    { id: 2, type: 'Malware Detection', severity: 'medium', status: 'active', timestamp: '2024-01-15 11:30:00' }
  ]
};

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, 'kasapa-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// API Routes
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Demo credentials for testing
  const demoCredentials = {
    'admin@kasapafm.com': { password: 'admin123', role: 'admin', name: 'System Administrator' },
    'tech@kasapafm.com': { password: 'tech123', role: 'technician', name: 'Broadcast Technician' },
    'journalist@kasapafm.com': { password: 'journo123', role: 'journalist', name: 'News Reporter' }
  };
  
  if (demoCredentials[email] && password === demoCredentials[email].password) {
    const token = jwt.sign(
      { 
        email: email, 
        role: demoCredentials[email].role,
        name: demoCredentials[email].name 
      },
      'kasapa-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        email: email,
        name: demoCredentials[email].name,
        role: demoCredentials[email].role,
        department: email.includes('admin') ? 'it' : 
                   email.includes('tech') ? 'studio' : 'newsroom'
      }
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }
});

app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/dashboard', authenticate, (req, res) => {
  const stats = {
    total_staff: mockDB.users.length,
    active_incidents: mockDB.incidents.filter(i => i.status !== 'closed' && i.status !== 'resolved').length,
    pending_alerts: mockDB.alerts.filter(a => a.status === 'active').length,
    online_devices: mockDB.devices.filter(d => d.status === 'online').length,
    system_status: 'secure',
    broadcast_status: 'online',
    network_status: 'stable',
    last_backup: '2024-01-14 23:00:00'
  };
  
  res.json({
    success: true,
    stats: stats,
    recent_incidents: mockDB.incidents.slice(0, 5),
    active_alerts: mockDB.alerts.filter(a => a.status === 'active'),
    devices: mockDB.devices
  });
});

app.get('/api/incidents', authenticate, (req, res) => {
  res.json({
    success: true,
    incidents: mockDB.incidents
  });
});

app.post('/api/incidents', authenticate, (req, res) => {
  const { title, description, category, severity } = req.body;
  
  const newIncident = {
    id: `INC-${Date.now()}`,
    title,
    description,
    category,
    severity: severity || 'medium',
    status: 'reported',
    reported_by: req.user.name,
    reported_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
  };
  
  mockDB.incidents.unshift(newIncident);
  
  res.json({
    success: true,
    message: 'Incident reported successfully',
    incident: newIncident
  });
});

app.get('/api/alerts', authenticate, (req, res) => {
  res.json({
    success: true,
    alerts: mockDB.alerts
  });
});

app.get('/api/devices', authenticate, (req, res) => {
  res.json({
    success: true,
    devices: mockDB.devices
  });
});

app.get('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  
  res.json({
    success: true,
    users: mockDB.users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
      last_login: new Date().toISOString()
    }))
  });
});

app.post('/api/register', (req, res) => {
  const { firstName, lastName, email, password, department, role } = req.body;
  
  // Check if user already exists
  if (mockDB.users.find(u => u.email === email)) {
    return res.status(400).json({
      success: false,
      message: 'User already exists'
    });
  }
  
  const newUser = {
    id: mockDB.users.length + 1,
    email,
    password: password, // In real app, hash this
    name: `${firstName} ${lastName}`,
    role: role || 'viewer',
    department: department || 'newsroom'
  };
  
  mockDB.users.push(newUser);
  
  res.json({
    success: true,
    message: 'Registration request submitted successfully',
    user: {
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
      department: newUser.department
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`===========================================`);
  console.log(`Kasapa FM Cybersecurity System`);
  console.log(`Server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser`);
  console.log(`===========================================`);
  console.log(`Demo Credentials:`);
  console.log(`Admin: admin@kasapafm.com / admin123`);
  console.log(`Technician: tech@kasapafm.com / tech123`);
  console.log(`Journalist: journalist@kasapafm.com / journo123`);
  console.log(`===========================================`);
});