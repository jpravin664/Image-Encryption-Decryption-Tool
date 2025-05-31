from flask import Flask, render_template, request, url_for, redirect, flash
from io import BytesIO
from PIL import Image, UnidentifiedImageError
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
import uuid
import magic
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size
csrf = CSRFProtect(app)

# Utility function to generate a unique filename
def generate_filename(extension):
    return f"{uuid.uuid4().hex}.{extension}"

def scan_for_malware(file):
    try:
        # Read the file content
        file.seek(0)
        file_content = file.read()

        # Simple checks for common patterns in malware (e.g., embedded scripts)
        if re.search(br'(<\?php|<script|eval\(|base64_decode\()', file_content):
            flash("WARNING: Malicious content detected! The file appears to contain potentially harmful scripts. Please upload a clean image file.", "danger")
            return False
        
        # Further heuristic checks can be added here
        file.seek(0)  # Reset file pointer after reading
        return True
    except Exception as e:
        flash(f"An error occurred during malware scanning: {str(e)}", "danger")
        return False
    
def validate_image(file):
    try:
        # Check if the file is an image based on MIME type
        mime_type = file.content_type
        if mime_type not in ['image/jpeg', 'image/png', 'image/gif']:
            flash("Unsupported image format. Please upload JPEG, PNG, or GIF.", "danger")
            return False

        # Check the file signature using python-magic
        file.seek(0)
        file_signature = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)  # Reset file pointer after reading

        if file_signature not in ['image/jpeg', 'image/png', 'image/gif']:
            flash(f"Unsupported file type: {file_signature}. Please upload a valid image file.", "danger")
            return False

        # Check if the file can be opened and recognized by PIL as an image
        try:
            img = Image.open(file)
            img.verify()  # This will raise an exception if the file is not a valid image
        except (UnidentifiedImageError, IOError):
            flash("The file is not a valid image or is corrupted.", "danger")
            return False
        finally:
            file.seek(0)  # Reset the file pointer to the beginning after reading

        # Check image dimensions
        width, height = img.size
        if width > 4000 or height > 4000:
            flash("Image dimensions too large. Maximum allowed is 4000x4000 pixels.", "danger")
            return False

        return True
    except Exception as e:
        flash(f"An error occurred during file validation: {str(e)}", "danger")
        return False

def compress_image(image):
    img = Image.open(image)
    img = img.convert('RGB')
    img_io = BytesIO()
    img.save(img_io, 'JPEG', quality=70)  # Compress the image
    img_io.seek(0)
    return img_io

def encrypt_image(image_data, key):
    iv = os.urandom(16)
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(image_data, AES.block_size))
    return encrypted_data

def decrypt_image(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

@app.route('/')
def index():
    return render_template('index.html', encrypted_image=None, decrypted_image=None)

@app.route('/encrypt', methods=['POST'])
@csrf.exempt  # Consider removing this exemption for security
def encrypt():
    key = request.form['key']
    image = request.files['image']
    if not image or not key:
        flash("Key and image are required.", "danger")
        return redirect(url_for('index'))

    if not validate_image(image) or not scan_for_malware(image):
        return redirect(url_for('index'))

    filename = secure_filename(image.filename)
    compressed_image = compress_image(image)
    image_data = compressed_image.read()
    encrypted_data = encrypt_image(image_data, key)
    encrypted_image_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    encrypted_image_data_url = f"data:image/jpeg;base64,{encrypted_image_base64}"
    
    return render_template('index.html', encrypted_image=encrypted_image_data_url, key=key, encrypted_image_base64=encrypted_image_base64)


@app.route('/decrypt', methods=['POST'])
@csrf.exempt  # Consider removing this exemption for security
def decrypt():
    key = request.form['key']
    encrypted_image = request.form['encrypted_image']
    if not encrypted_image or not key:
        flash("Key and encrypted image are required.", "danger")
        return redirect(url_for('index'))
    
    try:
        encrypted_data = base64.b64decode(encrypted_image)
        decrypted_data = decrypt_image(encrypted_data, key)
    except (ValueError, KeyError):
        flash("Invalid key or corrupted data.", "danger")
        return redirect(url_for('index'))

    decrypted_image = BytesIO(decrypted_data)
    image = Image.open(decrypted_image)
    filename = generate_filename('jpg')
    decrypted_image_path = os.path.join(app.static_folder, filename)
    image.save(decrypted_image_path)
    
    # Return the URL of the decrypted image
    decrypted_image_url = url_for('static', filename=filename)
    
    return render_template('index.html', 
                           encrypted_image=request.form['encrypted_image'], 
                           key=key, 
                           encrypted_image_base64=request.form['encrypted_image'],
                           decrypted_image=decrypted_image_url)

if __name__ == '__main__':
    app.run(debug=True)

