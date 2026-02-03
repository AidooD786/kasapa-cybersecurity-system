// Authentication Logic for Kasapa FM Cybersecurity Portal - Node.js Version

const API_BASE_URL = 'http://localhost:3000/api';

// Check if user is already logged in
document.addEventListener('DOMContentLoaded', function() {
    const currentUser = getCurrentUser();
    
    // Redirect logged-in users from login/signup pages
    if (currentUser && (window.location.pathname.includes('login.html') || 
                       window.location.pathname.includes('signup.html'))) {
        redirectBasedOnRole(currentUser.role);
    }
    
    // Show logout button if logged in
    updateAuthUI(currentUser);
    
    // Setup event listeners
    setupAuthForms();
});

// Get current user from localStorage
function getCurrentUser() {
    const userData = localStorage.getItem('kasapa_user');
    const token = localStorage.getItem('kasapa_token');
    
    if (userData && token) {
        return JSON.parse(userData);
    }
    return null;
}

// Update UI based on auth status
function updateAuthUI(user) {
    const loginBtn = document.querySelector('.btn-login');
    const signupBtn = document.querySelector('.btn-signup');
    const userMenu = document.querySelector('.user-menu');
    
    if (user) {
        // Replace login/signup with user info
        if (loginBtn && signupBtn) {
            loginBtn.style.display = 'none';
            signupBtn.style.display = 'none';
            
            // Create user menu if it doesn't exist
            if (!userMenu) {
                const navLinks = document.querySelector('.nav-links');
                const userMenuHTML = `
                    <div class="user-menu">
                        <div class="user-info">
                            <i class="fas fa-user-circle"></i>
                            <span>${user.name}</span>
                            <i class="fas fa-chevron-down"></i>
                        </div>
                        <div class="dropdown-menu">
                            <a href="dashboard.html"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                            <a href="profile.html"><i class="fas fa-user-cog"></i> Profile</a>
                            <div class="divider"></div>
                            <a href="#" id="logoutBtn"><i class="fas fa-sign-out-alt"></i> Logout</a>
                        </div>
                    </div>
                `;
                navLinks.innerHTML += userMenuHTML;
                
                // Add logout event listener
                document.getElementById('logoutBtn').addEventListener('click', logout);
            }
        }
    }
}

// Setup authentication forms
function setupAuthForms() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }
    
    // Password visibility toggles
    setupPasswordToggles();
    
    // MFA input handling
    setupMFAInputs();
    
    // Password strength meter
    setupPasswordStrength();
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    if (!validateEmail(email)) {
        showMessage('Please enter a valid email address', 'error');
        return;
    }
    
    if (password.length < 6) {
        showMessage('Password must be at least 6 characters', 'error');
        return;
    }
    
    showMessage('Authenticating...', 'info');
    
    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Save user data and token
            localStorage.setItem('kasapa_user', JSON.stringify(data.user));
            localStorage.setItem('kasapa_token', data.token);
            
            showMessage('Login successful! Redirecting...', 'success');
            
            // Redirect based on role
            setTimeout(() => {
                redirectBasedOnRole(data.user.role);
            }, 1500);
        } else {
            showMessage(data.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('Network error. Please try again.', 'error');
    }
}

// Handle signup
async function handleSignup(e) {
    e.preventDefault();
    
    const firstName = document.getElementById('firstName').value;
    const lastName = document.getElementById('lastName').value;
    const email = document.getElementById('email').value;
    const department = document.getElementById('department').value;
    const role = document.querySelector('input[name="role"]:checked')?.value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const agreeTerms = document.getElementById('agreeTerms').checked;
    
    // Validation
    if (!firstName || !lastName) {
        showMessage('Please enter your full name', 'error');
        return;
    }
    
    if (!validateEmail(email)) {
        showMessage('Please enter a valid work email', 'error');
        return;
    }
    
    if (!department) {
        showMessage('Please select your department', 'error');
        return;
    }
    
    if (!role) {
        showMessage('Please select a role', 'error');
        return;
    }
    
    if (password.length < 8) {
        showMessage('Password must be at least 8 characters', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showMessage('Passwords do not match', 'error');
        return;
    }
    
    if (!agreeTerms) {
        showMessage('You must agree to the cybersecurity policy', 'error');
        return;
    }
    
    showMessage('Submitting registration request...', 'info');
    
    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                firstName,
                lastName,
                email,
                password,
                department,
                role
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showMessage(
                'Registration request submitted successfully! A manager will review your request.',
                'success'
            );
            
            // Clear form
            e.target.reset();
            
            // Redirect to login after 3 seconds
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 3000);
        } else {
            showMessage(data.message || 'Registration failed', 'error');
        }
    } catch (error) {
        console.error('Signup error:', error);
        showMessage('Network error. Please try again.', 'error');
    }
}

// Redirect based on user role
function redirectBasedOnRole(role) {
    switch(role) {
        case 'admin':
            window.location.href = 'admin.html';
            break;
        case 'technician':
        case 'journalist':
        case 'analyst':
            window.location.href = 'dashboard.html';
            break;
        default:
            window.location.href = 'index.html';
    }
}

// Logout function
async function logout() {
    try {
        const token = localStorage.getItem('kasapa_token');
        
        if (token) {
            await fetch(`${API_BASE_URL}/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Clear local storage
        localStorage.removeItem('kasapa_user');
        localStorage.removeItem('kasapa_token');
        
        // Redirect to home page
        window.location.href = 'index.html';
    }
}

// Helper functions (keep these from previous version)
function setupPasswordToggles() {
    // Same as before
}

function setupMFAInputs() {
    // Same as before
}

function setupPasswordStrength() {
    // Same as before
}

function calculatePasswordStrength(password) {
    // Same as before
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function showMessage(message, type) {
    // Same as before, but simplified
    alert(`${type.toUpperCase()}: ${message}`);
}