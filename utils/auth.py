import streamlit as st
import sqlite3
import hashlib
import os
from datetime import datetime
import secrets
import json

# Database setup
DB_NAME = "legal_assistant.db"

def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except sqlite3.Error as e:
        st.error(f"Database connection error: {e}")
        return None

def init_db():
    """Initialize SQLite database with proper error handling"""
    conn = get_db_connection()
    if conn is None:
        return False
    
    cursor = conn.cursor()
    
    try:
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT,
                last_login TIMESTAMP
            )
        ''')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Drafts table to store all drafts in database
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                case_type TEXT,
                draft_content TEXT,
                medical_text TEXT,
                case_details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Training documents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_name TEXT,
                document_type TEXT,
                content TEXT,
                uploaded_by TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default admin user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_password_hash = hash_password("admin123")
            cursor.execute('''
                INSERT INTO users (username, password_hash, name, email, role, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', admin_password_hash, 'System Administrator', 'admin@legalfirm.com', 'admin', 'system'))
            st.success("Default admin user created: admin/admin123")
        
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        st.error(f"Database initialization error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Verify password against hash"""
    return hash_password(password) == password_hash

def initialize_authentication():
    """Initialize session state for authentication"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'name' not in st.session_state:
        st.session_state.name = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    
    # Initialize database
    if not init_db():
        st.error("Failed to initialize database. Please check the application logs.")

def login():
    """Login form with SQLite authentication"""
    with st.form("login_form"):
        st.subheader("Login to Legal Draft Assistant")
        
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        login_button = st.form_submit_button("Login")
        
        if login_button:
            if not username or not password:
                st.error("Please enter both username and password")
            else:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.username = user['username']
                    st.session_state.user_role = user['role']
                    st.session_state.name = user['name']
                    st.session_state.user_id = user['id']
                    
                    # Update last login
                    update_last_login(user['id'])
                    
                    # Log login action
                    log_audit_action(user['id'], user['username'], "LOGIN", "User logged in successfully")
                    
                    # Load user's draft history from database
                    load_user_drafts(user['id'])
                    
                    st.success(f"Welcome {user['name']}!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")
    
    return st.session_state.authenticated

def authenticate_user(username, password):
    """Authenticate user against database"""
    conn = get_db_connection()
    if conn is None:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, name, role 
            FROM users 
            WHERE username = ? AND active = 1
        ''', (username,))
        
        user = cursor.fetchone()
        if user and verify_password(password, user['password_hash']):
            return {
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'role': user['role']
            }
        return None
    except sqlite3.Error as e:
        st.error(f"Authentication error: {e}")
        return None
    finally:
        conn.close()

def update_last_login(user_id):
    """Update user's last login timestamp"""
    conn = get_db_connection()
    if conn is None:
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error updating last login: {e}")
        conn.rollback()
    finally:
        conn.close()

def create_user(username, password, name, email, role, created_by):
    """Create a new user in database"""
    conn = get_db_connection()
    if conn is None:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, name, email, role, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, name, email, role, created_by))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        # Log the action
        creator_username = get_username_by_id(created_by)
        log_audit_action(created_by, creator_username, "CREATE_USER", f"Created user: {username}")
        
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"
    except Exception as e:
        return False, f"Error creating user: {str(e)}"
    finally:
        conn.close()

def update_user(user_id, **kwargs):
    """Update user information with proper error handling"""
    if not user_id:
        return False, "Invalid user ID"
    
    conn = get_db_connection()
    if conn is None:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        update_fields = []
        update_values = []
        
        for key, value in kwargs.items():
            if key == 'password' and value:
                update_fields.append("password_hash = ?")
                update_values.append(hash_password(value))
            elif key in ['name', 'email', 'role'] and value is not None:
                update_fields.append(f"{key} = ?")
                update_values.append(value)
        
        if not update_fields:
            return False, "No valid fields to update"
        
        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        
        affected_rows = cursor.rowcount
        conn.commit()
        
        if affected_rows == 0:
            return False, "User not found or no changes made"
        
        # Log the action
        log_audit_action(st.session_state.user_id, st.session_state.username, "UPDATE_USER", f"Updated user ID: {user_id}")
        
        return True, "User updated successfully"
    except sqlite3.Error as e:
        conn.rollback()
        return False, f"Database error: {str(e)}"
    except Exception as e:
        conn.rollback()
        return False, f"Error updating user: {str(e)}"
    finally:
        conn.close()

def delete_user(user_id, username):
    """Soft delete a user with proper error handling"""
    if not user_id:
        return False, "Invalid user ID"
    
    if username == "admin":
        return False, "Cannot delete admin user"
    
    conn = get_db_connection()
    if conn is None:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        
        # First, verify the user exists and is active
        cursor.execute('SELECT username FROM users WHERE id = ? AND active = 1', (user_id,))
        user_exists = cursor.fetchone()
        
        if not user_exists:
            return False, "User not found or already deleted"
        
        # Perform the soft delete
        cursor.execute('UPDATE users SET active = 0 WHERE id = ?', (user_id,))
        affected_rows = cursor.rowcount
        conn.commit()
        
        if affected_rows == 0:
            return False, "No user was deleted"
        
        # Log the action
        log_audit_action(st.session_state.user_id, st.session_state.username, "DELETE_USER", f"Deleted user: {username} (ID: {user_id})")
        
        return True, f"User '{username}' deleted successfully"
    except sqlite3.Error as e:
        conn.rollback()
        return False, f"Database error: {str(e)}"
    except Exception as e:
        conn.rollback()
        return False, f"Error deleting user: {str(e)}"
    finally:
        conn.close()

def get_all_users():
    """Get all active users with proper error handling"""
    conn = get_db_connection()
    if conn is None:
        return {}
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, name, email, role, created_at, created_by, last_login
            FROM users 
            WHERE active = 1
            ORDER BY username
        ''')
        
        users = cursor.fetchall()
        user_dict = {}
        
        for user in users:
            user_dict[user['username']] = {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'created_at': user['created_at'],
                'created_by': user['created_by'],
                'last_login': user['last_login']
            }
        
        return user_dict
    except sqlite3.Error as e:
        st.error(f"Error fetching users: {e}")
        return {}
    finally:
        conn.close()

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    if conn is None:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, name, role FROM users WHERE username = ? AND active = 1', (username,))
        user = cursor.fetchone()
        
        if user:
            return {
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'role': user['role']
            }
        return None
    except sqlite3.Error as e:
        st.error(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_username_by_id(user_id):
    """Get username by user ID"""
    conn = get_db_connection()
    if conn is None:
        return "Unknown"
    
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        return result['username'] if result else "Unknown"
    except sqlite3.Error:
        return "Unknown"
    finally:
        conn.close()

def log_audit_action(user_id, username, action, details):
    """Log user actions to audit trail"""
    conn = get_db_connection()
    if conn is None:
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (user_id, username, action, details)
            VALUES (?, ?, ?, ?)
        ''', (user_id, username, action, details))
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error logging audit action: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_audit_logs(limit=100):
    """Get audit logs"""
    conn = get_db_connection()
    if conn is None:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT al.timestamp, al.username, al.action, al.details, u.name
            FROM audit_log al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        return cursor.fetchall()
    except sqlite3.Error as e:
        st.error(f"Error fetching audit logs: {e}")
        return []
    finally:
        conn.close()

def save_draft_to_db(user_id, username, case_type, draft_content, medical_text, case_details):
    """Save draft to database"""
    conn = get_db_connection()
    if conn is None:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO drafts (user_id, username, case_type, draft_content, medical_text, case_details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, case_type, draft_content, medical_text, json.dumps(case_details)))
        
        draft_id = cursor.lastrowid
        conn.commit()
        
        # Log the action
        log_audit_action(user_id, username, "SAVE_DRAFT", f"Saved draft for case: {case_type}")
        
        return draft_id
    except Exception as e:
        st.error(f"Error saving draft: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def load_user_drafts(user_id):
    """Load user's drafts from database into session state"""
    conn = get_db_connection()
    if conn is None:
        st.session_state.draft_history = []
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT case_type, draft_content, created_at 
            FROM drafts 
            WHERE user_id = ? 
            ORDER BY created_at DESC
            LIMIT 50
        ''', (user_id,))
        
        drafts = cursor.fetchall()
        
        # Convert to session state format
        st.session_state.draft_history = []
        for draft in drafts:
            st.session_state.draft_history.append({
                'timestamp': draft['created_at'],
                'case_type': draft['case_type'],
                'user': st.session_state.username,
                'content': draft['draft_content']
            })
    except sqlite3.Error as e:
        st.error(f"Error loading drafts: {e}")
        st.session_state.draft_history = []
    finally:
        conn.close()

def get_user_drafts_count(user_id):
    """Get count of drafts for a user"""
    conn = get_db_connection()
    if conn is None:
        return 0
    
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM drafts WHERE user_id = ?', (user_id,))
        count = cursor.fetchone()[0]
        return count
    except sqlite3.Error:
        return 0
    finally:
        conn.close()

def get_all_drafts_stats():
    """Get statistics about all drafts"""
    conn = get_db_connection()
    if conn is None:
        return {'total_drafts': 0, 'drafts_by_type': {}, 'recent_drafts': []}
    
    try:
        cursor = conn.cursor()
        
        # Total drafts count
        cursor.execute('SELECT COUNT(*) FROM drafts')
        total_drafts = cursor.fetchone()[0]
        
        # Drafts by case type
        cursor.execute('''
            SELECT case_type, COUNT(*) 
            FROM drafts 
            GROUP BY case_type 
            ORDER BY COUNT(*) DESC
        ''')
        drafts_by_type = dict(cursor.fetchall())
        
        # Recent drafts
        cursor.execute('''
            SELECT username, case_type, created_at 
            FROM drafts 
            ORDER BY created_at DESC 
            LIMIT 10
        ''')
        recent_drafts = cursor.fetchall()
        
        return {
            'total_drafts': total_drafts,
            'drafts_by_type': drafts_by_type,
            'recent_drafts': recent_drafts
        }
    except sqlite3.Error:
        return {'total_drafts': 0, 'drafts_by_type': {}, 'recent_drafts': []}
    finally:
        conn.close()

def save_training_doc(document_name, document_type, content, uploaded_by):
    """Save training document to database"""
    conn = get_db_connection()
    if conn is None:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO training_docs (document_name, document_type, content, uploaded_by)
            VALUES (?, ?, ?, ?)
        ''', (document_name, document_type, content, uploaded_by))
        
        conn.commit()
        
        # Log the action
        log_audit_action(st.session_state.user_id, st.session_state.username, "UPLOAD_TRAINING_DOC", f"Uploaded: {document_name}")
        
        return True
    except Exception as e:
        st.error(f"Error saving training doc: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_training_docs():
    """Get all training documents"""
    conn = get_db_connection()
    if conn is None:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT document_name, document_type, uploaded_by, uploaded_at 
            FROM training_docs 
            ORDER BY uploaded_at DESC
        ''')
        
        return cursor.fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

def get_user_role(username):
    """Get user role"""
    user = get_user_by_username(username)
    return user['role'] if user else "staff"

def check_authentication():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def test_database_connection():
    """Test database connection and basic operations with detailed info"""
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            
            # Get table info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            # Get user count
            cursor.execute("SELECT COUNT(*) FROM users WHERE active = 1")
            active_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE active = 0")
            inactive_users = cursor.fetchone()[0]
            
            # Get draft count
            cursor.execute("SELECT COUNT(*) FROM drafts")
            draft_count = cursor.fetchone()[0]
            
            conn.close()
            
            return True, f"Database connected. Tables: {[table['name'] for table in tables]}. Active users: {active_users}, Inactive users: {inactive_users}, Drafts: {draft_count}"
        else:
            return False, "Failed to connect to database"
    except Exception as e:
        return False, f"Database test failed: {str(e)}"

def debug_get_all_users_including_inactive():
    """Get all users including inactive ones for debugging"""
    conn = get_db_connection()
    if conn is None:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, name, email, role, active, created_at
            FROM users 
            ORDER BY username
        ''')
        
        users = cursor.fetchall()
        return users
    except sqlite3.Error as e:
        print(f"Debug error: {e}")
        return []
    finally:
        conn.close()