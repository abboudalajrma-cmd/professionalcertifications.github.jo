import pandas as pd
import sqlite3
import os
import json
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- إعدادات المسارات وقاعدة البيانات ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'archive_v3.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT)')
        conn.execute('''CREATE TABLE IF NOT EXISTS indexed_data (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            file_id INTEGER,
                            sheet_name TEXT,
                            content_json TEXT,
                            search_vector TEXT
                        )''')
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)')
        
        # إضافة مستخدم admin افتراضي إذا لم يوجد
        admin_exists = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin_exists:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         ('admin', generate_password_hash('admin123')))
        conn.commit()

init_db()

# --- إدارة تسجيل الدخول ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'])
    return None

# --- المسارات الأساسية ---

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST" and current_user.username == 'admin':
        file = request.files.get('file')
        if file and file.filename:
            try:
                excel_dict = pd.read_excel(BytesIO(file.read()), sheet_name=None)
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    existing_file = cursor.execute('SELECT id FROM files WHERE filename = ?', (file.filename,)).fetchone()
                    
                    if existing_file:
                        file_id = existing_file['id']
                        conn.execute('DELETE FROM indexed_data WHERE file_id = ?', (file_id,))
                    else:
                        cursor.execute('INSERT INTO files (filename) VALUES (?)', (file.filename,))
                        file_id = cursor.lastrowid
                    
                    for sheet, df in excel_dict.items():
                        for col in df.columns:
                            if pd.api.types.is_datetime64_any_dtype(df[col]):
                                df[col] = df[col].dt.strftime('%Y-%m-%d')
                        
                        df = df.fillna('').astype(str)
                        for _, row in df.iterrows():
                            row_dict = row.to_dict()
                            search_vector = " ".join(row_dict.values()).lower()
                            conn.execute('''INSERT INTO indexed_data (file_id, sheet_name, content_json, search_vector) 
                                            VALUES (?, ?, ?, ?)''', 
                                         (file_id, sheet, json.dumps(row_dict, ensure_ascii=False), search_vector))
                    conn.commit()
                flash(f"تم تحديث بيانات '{file.filename}' بنجاح")
            except Exception as e:
                flash(f"خطأ في الرفع: {e}")
    
    # جلب جميع أسماء الأوراق لعرضها في الفلتر
    with get_db_connection() as conn:
        all_sheets = [r['sheet_name'] for r in conn.execute('SELECT DISTINCT sheet_name FROM indexed_data').fetchall()]
    return render_template("index.html", is_search=False, all_sheets=all_sheets)

@app.route("/search_all", methods=["POST"])
@login_required
def search_all():
    query = request.form.get('query', '').lower().strip()
    selected_sheet = request.form.get('sheet_filter', '') # استقبال الفلتر من الواجهة
    
    if not query: return redirect(url_for('index'))
    
    search_results = []
    with get_db_connection() as conn:
        # تعديل الاستعلام ليشمل شرط اسم الورقة إذا تم اختياره
        sql = '''SELECT i.*, f.filename FROM indexed_data i 
                 JOIN files f ON i.file_id = f.id 
                 WHERE i.search_vector LIKE ?'''
        params = [f'%{query}%']
        
        if selected_sheet:
            sql += " AND i.sheet_name = ?"
            params.append(selected_sheet)
            
        rows = conn.execute(sql, params).fetchall()
        for row in rows:
            res = json.loads(row['content_json'])
            res.update({'_file': row['filename'], '_sheet': row['sheet_name']})
            search_results.append(res)
            
        # جلب قائمة الأوراق مجدداً لعرضها في الفلتر بصفحة النتائج
        all_sheets = [r['sheet_name'] for r in conn.execute('SELECT DISTINCT sheet_name FROM indexed_data').fetchall()]
            
    return render_template("index.html", search_data=search_results, is_search=True, 
                           search_query=query, all_sheets=all_sheets, current_sheet=selected_sheet)

# باقي الدوال (files, delete, manage_users, login, logout) تبقى كما هي في ملفك الأصلي

@app.route("/files")
@login_required
def list_files():
    with get_db_connection() as conn:
        files = conn.execute('SELECT id, filename FROM files').fetchall()
    return render_template("files.html", files=files)

@app.route("/delete/<int:file_id>")
@login_required
def delete_file(file_id):
    if current_user.username == 'admin':
        with get_db_connection() as conn:
            conn.execute('DELETE FROM indexed_data WHERE file_id = ?', (file_id,))
            conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
            conn.commit()
            flash("تم حذف الملف وكافة بياناته بنجاح")
    return redirect(url_for('list_files'))

@app.route("/users")
@login_required
def manage_users():
    if current_user.username != 'admin': return redirect(url_for('index'))
    with get_db_connection() as conn:
        users = conn.execute('SELECT id, username FROM users').fetchall()
    return render_template("manage_users.html", users=users)

@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.username != 'admin': return redirect(url_for('index'))
    user, pw = request.form.get('username'), request.form.get('password')
    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         (user, generate_password_hash(pw)))
            conn.commit()
            flash("تمت إضافة المستخدم بنجاح")
    except: flash("خطأ: اسم المستخدم موجود مسبقاً")
    return redirect(url_for('manage_users'))

# --- تسجيل الدخول ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (u,)).fetchone()
            if user and check_password_hash(user['password'], p):
                login_user(User(user['id'], user['username']))
                return redirect(url_for('index'))
        flash('بيانات الدخول غير صحيحة')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user(); return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)