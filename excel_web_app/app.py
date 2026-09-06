import os
import json
import sqlite3
from io import BytesIO
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# مفتاح سري ثابت لضمان استقرار الجلسات والتنبيهات
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_12345')

# --- إعدادات المسارات وقاعدة البيانات ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'archive_v3.db')

ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    all_sheets = []
    try:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT DISTINCT sheet_name FROM indexed_data WHERE sheet_name IS NOT NULL AND sheet_name != ""').fetchall()
            all_sheets = [r['sheet_name'] for r in rows]
    except Exception:
        pass

    if request.method == "POST" and current_user.username == 'admin':
        file = request.files.get('file')
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("خطأ: نوع الملف غير مدعوم. يرجى رفع ملف Excel فقط (.xlsx, .xls)", "error")
                return redirect(url_for('index'))
                
            try:
                file_bytes = file.read()
                with BytesIO(file_bytes) as data_stream:
                    excel_dict = pd.read_excel(data_stream, sheet_name=None, engine='openpyxl')
                
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    existing_file = cursor.execute('SELECT id FROM files WHERE filename = ?', (file.filename,)).fetchone()
                    
                    if existing_file:
                        file_id = existing_file['id']
                        conn.execute('DELETE FROM indexed_data WHERE file_id = ?', (file_id,))
                    else:
                        cursor.execute('INSERT INTO files (filename) VALUES (?)', (file.filename,))
                        file_id = cursor.lastrowid
                    
                    rows_to_insert = []
                    for sheet, df in excel_dict.items():
                        for col in df.columns:
                            if pd.api.types.is_datetime64_any_dtype(df[col]):
                                df[col] = df[col].dt.strftime('%Y-%m-%d')
                        
                        for col in df.columns:
                            if df[col].dtype == 'float64' or df[col].dtype == 'object':
                                df[col] = df[col].apply(lambda x: str(int(x)) if isinstance(x, float) and x.is_integer() else x)
                        
                        df = df.astype(str).replace(['nan', 'NaN', 'NaT'], '')
                        
                        for _, row in df.iterrows():
                            row_dict = row.to_dict()
                            search_vector = " ".join([v.strip() for v in row_dict.values() if v.strip()]).lower()
                            
                            rows_to_insert.append((
                                file_id, 
                                sheet, 
                                json.dumps(row_dict, ensure_ascii=False), 
                                search_vector
                            ))
                    
                    if rows_to_insert:
                        conn.executemany('''INSERT INTO indexed_data (file_id, sheet_name, content_json, search_vector) 
                                            VALUES (?, ?, ?, ?)''', rows_to_insert)
                    conn.commit()
                    
                flash("تم رفع الملف وتحديث البيانات بنجاح المجلد!", "success")
                return redirect(url_for('index'))
            except Exception as e:
                flash("خطأ أثناء معالجة وقراءة ملف الإكسل: " + str(e), "error")
                return redirect(url_for('index'))
    
    return render_template("index.html", 
                           is_search=False, 
                           all_sheets=all_sheets, 
                           search_query="", 
                           current_sheet="", 
                           search_data=[],
                           search_type="contains")

@app.route("/search_all", methods=["POST"])
@login_required
def search_all():
    query = request.form.get('query', '').lower().strip()
    selected_sheet = request.form.get('sheet_filter', '').strip()
    search_type = request.form.get('search_type', 'contains') 
    
    if not query and not selected_sheet: 
        flash("يرجى إدخال كلمة بحث أو اختيار ورقة عمل لتتمكن من الاستعلام", "error")
        return redirect(url_for('index'))
    
    search_results = []
    all_sheets = []
    try:
        with get_db_connection() as conn:
            all_sheets = [r['sheet_name'] for r in conn.execute('SELECT DISTINCT sheet_name FROM indexed_data WHERE sheet_name IS NOT NULL AND sheet_name != ""').fetchall()]
            
            sql = '''SELECT i.*, f.filename FROM indexed_data i 
                     JOIN files f ON i.file_id = f.id WHERE 1=1'''
            params = []
            
            if query:
                if search_type == 'exact':
                    sql += " AND (i.search_vector = ? OR i.search_vector LIKE ? OR i.search_vector LIKE ? OR i.search_vector LIKE ?)"
                    params.extend([query, query + " %", "% " + query, "% " + query + " %"])
                else:
                    sql += " AND i.search_vector LIKE ?"
                    params.append("%" + query + "%")
            
            if selected_sheet:
                sql += " AND i.sheet_name = ?"
                params.append(selected_sheet)
                
            rows = conn.execute(sql, params).fetchall()
            for row in rows:
                res = json.loads(row['content_json'])
                res.update({'_file': row['filename'], '_sheet': row['sheet_name']})
                search_results.append(res)
                
    except Exception as e:
        flash("حدث خطأ أثناء محاولة جلب البيانات: " + str(e), "error")
            
    return render_template("index.html", 
                           search_data=search_results, 
                           is_search=True, 
                           search_query=query, 
                           all_sheets=all_sheets, 
                           current_sheet=selected_sheet,
                           search_type=search_type)

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
            flash("تم حذف الملف المحدد وكافة السجلات التابعة له نهائياً", "success")
    return redirect(url_for('list_files'))

@app.route("/users")
@login_required
def manage_users():
    if current_user.username != 'admin': 
        return redirect(url_for('index'))
    with get_db_connection() as conn:
        users = conn.execute('SELECT id, username FROM users').fetchall()
    return render_template("manage_users.html", users=users)

@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.username != 'admin': 
        return redirect(url_for('index'))
    user, pw = request.form.get('username'), request.form.get('password')
    if not user or not pw:
        flash("خطأ: يرجى ملء جميع الحقول المطلوبة", "error")
        return redirect(url_for('manage_users'))
    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         (user, generate_password_hash(pw)))
            conn.commit()
            flash("تم إنشاء حساب المستخدم الجديد بنجاح", "success")
    except Exception: 
        flash("خطأ: اسم المستخدم هذا مسجل مسبقاً في النظام", "error")
    return redirect(url_for('manage_users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (u,)).fetchone()
            if user and check_password_hash(user['password'], p):
                login_user(User(user['id'], user['username']))
                return redirect(url_for('index'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحة!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- مسار قائمة الامتحانات والإحصاء الذكي بدون تكرار وبدون مسافات عشوائية ---
@app.route("/exams_list")
@login_required
def exams_list():
    exams_count = {}  # قاموس لتخزين اسم الامتحان وعدد السجلات
    try:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT content_json FROM indexed_data').fetchall()
            for row in rows:
                data = json.loads(row['content_json'])
                
                # فحص شامل وذكي لمفاتيح الأعمدة للوصول لاسم الامتحان أو البرنامج
                for key, value in data.items():
                    if any(word in key for word in ['اسم الامتحان']):
                        val_str = str(value).strip()
                        if val_str and val_str.lower() not in ['nan', 'none', '']:
                            if val_str in exams_count:
                                exams_count[val_str] += 1
                            else:
                                exams_count[val_str] = 1
    except Exception:
        pass
    
    # ترتيب مخرجات الامتحانات أبجدياً بشكل منسق
    sorted_exams = sorted(exams_count.items(), key=lambda x: x[0])
    return render_template("exams.html", exams=sorted_exams)
@app.route("/export_exams_excel")
@login_required
def export_exams_excel():
    exams_count = {}
    try:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT content_json FROM indexed_data').fetchall()
            for row in rows:
                data = json.loads(row['content_json'])
                for key, value in data.items():
                    if any(word in key for word in [ 'اسم الامتحان']):
                        val_str = str(value).strip()
                        if val_str and val_str.lower() not in ['nan', 'none', '']:
                            if val_str in exams_count:
                                exams_count[val_str] += 1
                            else:
                                exams_count[val_str] = 1
                                
        # تحويل البيانات إلى DataFrame لتصديرها
        sorted_exams = sorted(exams_count.items(), key=lambda x: x[0])
        df = pd.DataFrame(sorted_exams, columns=['اسم الامتحان / البرنامج', 'عدد الممتحنين'])
        
        # تحويل ملف الإكسل إلى بايتس لإرساله للمتصفح مباشرة دون حفظه على السيرفر
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='إحصائيات الامتحانات')
        output.seek(0)
        
        from flask import send_file
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name="قائمة_الامتحانات_والأعداد.xlsx"
        )
    except Exception as e:
        flash("حدث خطأ أثناء تصدير ملف الإكسل: " + str(e), "error")
        return redirect(url_for('exams_list'))
@app.route("/update_exam_name", methods=["POST"])
@login_required
def update_exam_name():
    # السماح فقط للمشرف (admin) بالتعديل
    if current_user.username != 'admin':
        flash("عذراً، لا تمتلك صلاحية تعديل البيانات", "error")
        return redirect(url_for('exams_list'))
        
    old_name = request.form.get('old_name', '').strip()
    new_name = request.form.get('new_name', '').strip()
    
    if not old_name or not new_name:
        flash("خطأ: يجب إدخال الاسم الجديد بشكل صحيح", "error")
        return redirect(url_for('exams_list'))
        
    updated_count = 0
    try:
        with get_db_connection() as conn:
            # جلب كل السجلات لتحديث الاسم داخل الـ JSON وفي متجه البحث
            rows = conn.execute('SELECT id, content_json, search_vector FROM indexed_data').fetchall()
            
            for row in rows:
                data = json.loads(row['content_json'])
                modified = False
                
                # البحث عن الاسم القديم وتحديثه
                for key, value in data.items():
                    if any(word in key for word in ['برنامج', 'امتحان', 'دورة', 'البرنامج', 'الامتحان', 'اسم الامتحان']):
                        if str(value).strip() == old_name:
                            data[key] = new_name
                            modified = True
                
                # إذا وجدنا الاسم وتعدل، نحفظ السجل في قاعدة البيانات
                if modified:
                    new_json = json.dumps(data, ensure_ascii=False)
                    # تحديث متجه البحث أيضاً ليعكس الاسم الجديد
                    new_vector = " ".join([v.strip() for v in data.values() if v.strip()]).lower()
                    
                    conn.execute('UPDATE indexed_data SET content_json = ?, search_vector = ? WHERE id = ?', 
                                 (new_json, new_vector, row['id']))
                    updated_count += 1
            
            conn.commit()
        flash(f"تم تحديث الاسم بنجاح في {updated_count} سجل/ممتحن!", "success")
    except Exception as e:
        flash("حدث خطأ أثناء التحديث: " + str(e), "error")
        
    return redirect(url_for('exams_list'))
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)