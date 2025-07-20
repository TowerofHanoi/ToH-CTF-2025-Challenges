import os
import sqlite3
import uuid
import shutil
from flask import Flask, render_template, request, redirect, url_for, send_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'database.sqlite'

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    with get_db_connection() as conn:
        files = conn.execute('SELECT * FROM files').fetchall()
    return render_template('index.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']

        if len(file.read()) > 0:
            return 'File size exceeds 0 bytes', 400
        
        uuid_file = str(uuid.uuid4())
        save_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

        if "../" in save_path or save_path.startswith("/"):
            return 'Invalid filename', 400
        
        file.save(save_path)
        
        with get_db_connection() as conn:
            conn.execute('INSERT INTO files (filename, uuid) VALUES (?, ?)', (file.filename, uuid_file))
            conn.commit()

        return redirect('uploads/'+uuid_file)
    
    return render_template('upload.html')

@app.route('/uploads/<uuid_file>')
def view_file(uuid_file):
    with get_db_connection() as conn:
        file = conn.execute('SELECT * FROM files WHERE uuid = ?', (uuid_file,)).fetchone()

    if file:
        path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
        return send_file(path)
    
    return 'File not found', 404

@app.route('/rename/<uuid_file>', methods=['POST'])
def move_file(uuid_file):
    new_filename = request.json.get('new_filename')
    with get_db_connection() as conn:
        try:
            conn.execute("BEGIN TRANSACTION")

            file = conn.execute('SELECT * FROM files WHERE uuid = ?', (uuid_file,)).fetchone()

            conn.execute('UPDATE files SET filename = ? WHERE uuid = ?', (new_filename, uuid_file))
            
            old_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
            new_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))

            if "../" in new_path or new_path.startswith("/"):
                return 'Invalid filename', 400
            
            shutil.move(old_path, new_path)

            conn.commit()
        except Exception as e:
            conn.rollback()
            return f'Operation failed {e}', 400
        
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0")