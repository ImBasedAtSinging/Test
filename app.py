# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import re
import hashlib
import os
from functools import wraps
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="your_password",
        database="task_manager"
    )

# Convert database cursor results to dictionaries
def dict_fetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

def dict_fetchone(cursor):
    row = cursor.fetchone()
    if row is None:
        return None
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for routes that require admin privileges
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session['role'] != 'admin':
            flash('Admin privileges required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password
        hash_obj = hashlib.sha256(password.encode())
        password_hash = hash_obj.hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password_hash))
        account = dict_fetchone(cursor)
        
        if account:
            # Create session data
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']
            
            # Redirect to dashboard
            return redirect(url_for('dashboard'))
        else:
            msg = 'Incorrect username/password!'
        
        cursor.close()
        conn.close()
    
    return render_template('login.html', msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = dict_fetchone(cursor)
        
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password
            hash_obj = hashlib.sha256(password.encode())
            password_hash = hash_obj.hexdigest()
            
            # Insert new account
            cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)', 
                          (username, password_hash, email))
            conn.commit()
            msg = 'You have successfully registered!'
        
        cursor.close()
        conn.close()
    
    return render_template('register.html', msg=msg)

@app.route('/logout')
def logout():
    # Remove session data
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)
    
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's task groups
    cursor.execute('SELECT * FROM task_groups WHERE user_id = %s ORDER BY created_at DESC', (session['id'],))
    task_groups = dict_fetchall(cursor)
    
    # Get tasks count for each group
    for group in task_groups:
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE group_id = %s', (group['id'],))
        count = dict_fetchone(cursor)
        group['task_count'] = count['count']
    
    cursor.close()
    conn.close()
    
    return render_template('dashboard.html', task_groups=task_groups)

@app.route('/task_group/<int:group_id>')
@login_required
def task_group(group_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get task group
    cursor.execute('SELECT * FROM task_groups WHERE id = %s AND user_id = %s', (group_id, session['id']))
    group = dict_fetchone(cursor)
    
    if not group:
        flash('Task group not found or you do not have permission to view it', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get tasks in the group
    cursor.execute('''
        SELECT t.*, GROUP_CONCAT(tg.name) as tags
        FROM tasks t
        LEFT JOIN task_tags tt ON t.id = tt.task_id
        LEFT JOIN tags tg ON tt.tag_id = tg.id
        WHERE t.group_id = %s
        GROUP BY t.id
        ORDER BY 
            CASE t.status 
                WHEN 'completed' THEN 3
                WHEN 'in_progress' THEN 2
                WHEN 'pending' THEN 1
            END,
            CASE t.priority
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
            END,
            t.due_date
    ''', (group_id,))
    tasks = dict_fetchall(cursor)
    
    # Get all available tags
    cursor.execute('SELECT * FROM tags ORDER BY name')
    tags = dict_fetchall(cursor)
    
    cursor.close()
    conn.close()
    
    return render_template('task_group.html', group=group, tasks=tasks, tags=tags)

@app.route('/create_task_group', methods=['GET', 'POST'])
@login_required
def create_task_group():
    if request.method == 'POST' and 'name' in request.form:
        name = request.form['name']
        description = request.form.get('description', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('INSERT INTO task_groups (name, description, user_id) VALUES (%s, %s, %s)',
                      (name, description, session['id']))
        conn.commit()
        
        group_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        flash('Task group created successfully!', 'success')
        return redirect(url_for('task_group', group_id=group_id))
    
    return render_template('create_task_group.html')

@app.route('/create_task/<int:group_id>', methods=['GET', 'POST'])
@login_required
def create_task(group_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if group exists and belongs to user
    cursor.execute('SELECT * FROM task_groups WHERE id = %s AND user_id = %s', (group_id, session['id']))
    group = dict_fetchone(cursor)
    
    if not group:
        flash('Task group not found or you do not have permission to add tasks to it', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST' and 'title' in request.form:
        title = request.form['title']
        description = request.form.get('description', '')
        priority = request.form.get('priority', 'medium')
        due_date_str = request.form.get('due_date', '')
        due_date = None if not due_date_str else datetime.strptime(due_date_str, '%Y-%m-%d').date()
        
        # Insert task
        cursor.execute('''
            INSERT INTO tasks (title, description, priority, due_date, group_id)
            VALUES (%s, %s, %s, %s, %s)
        ''', (title, description, priority, due_date, group_id))
        conn.commit()
        
        task_id = cursor.lastrowid
        
        # Add tags if selected
        if 'tags' in request.form:
            tags = request.form.getlist('tags')
            for tag_id in tags:
                cursor.execute('INSERT INTO task_tags (task_id, tag_id) VALUES (%s, %s)', (task_id, tag_id))
            conn.commit()
        
        flash('Task created successfully!', 'success')
        return redirect(url_for('task_group', group_id=group_id))
    
    # Get all available tags
    cursor.execute('SELECT * FROM tags ORDER BY name')
    tags = dict_fetchall(cursor)
    
    cursor.close()
    conn.close()
    
    return render_template('create_task.html', group=group, tags=tags)

@app.route('/update_task_status/<int:task_id>/<status>')
@login_required
def update_task_status(task_id, status):
    if status not in ['pending', 'in_progress', 'completed']:
        flash('Invalid status', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if task exists and belongs to user
    cursor.execute('''
        SELECT t.*, tg.user_id 
        FROM tasks t
        JOIN task_groups tg ON t.group_id = tg.id
        WHERE t.id = %s
    ''', (task_id,))
    task = dict_fetchone(cursor)
    
    if not task or task['user_id'] != session['id']:
        flash('Task not found or you do not have permission to update it', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update task status
    cursor.execute('UPDATE tasks SET status = %s WHERE id = %s', (status, task_id))
    conn.commit()
    
    cursor.close()
    conn.close()
    
    flash('Task status updated successfully!', 'success')
    return redirect(url_for('task_group', group_id=task['group_id']))

@app.route('/manage_tags', methods=['GET', 'POST'])
@admin_required
def manage_tags():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST' and 'name' in request.form:
        name = request.form['name']
        color = request.form.get('color', '#cccccc')
        
        cursor.execute('INSERT INTO tags (name, color) VALUES (%s, %s)', (name, color))
        conn.commit()
        
        flash('Tag created successfully!', 'success')
        return redirect(url_for('manage_tags'))
    
    # Get all tags
    cursor.execute('SELECT * FROM tags ORDER BY name')
    tags = dict_fetchall(cursor)
    
    cursor.close()
    conn.close()
    
    return render_template('manage_tags.html', tags=tags)

@app.route('/admin/users')
@admin_required
def manage_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users ORDER BY username')
    users = dict_fetchall(cursor)
    
    cursor.close()
    conn.close()
    
    return render_template('manage_users.html', users=users)

@app.route('/admin/update_user_role/<int:user_id>/<role>')
@admin_required
def update_user_role(user_id, role):
    if role not in ['admin', 'regular']:
        flash('Invalid role', 'danger')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('UPDATE users SET role = %s WHERE id = %s', (role, user_id))
    conn.commit()
    
    cursor.close()
    conn.close()
    
    flash('User role updated successfully!', 'success')
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(debug=True)
    