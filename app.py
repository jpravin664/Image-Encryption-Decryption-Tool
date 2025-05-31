import os
import re
import uuid
import base64
import magic
from io import BytesIO
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, url_for, redirect, flash, abort
from PIL import Image, UnidentifiedImageError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from flask_wtf.csrf import CSRFProtect

# Initialize Flask app
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY') or os.urandom(32),
    'UPLOAD_FOLDER': 'uploads',
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB max file size
    'ALLOWED_EXTENSIONS': {'jpg', 'jpeg', 'png', 'gif'},
    'MAX_IMAGE_DIMENSION': 4000,
    'COMPRESSION_QUALITY': 70,
    'AES_KEY_SIZE': 32  # 256-bit key
})

# Enable CSRF protection globally
csrf = CSRFProtect(app)

# Custom error handlers
@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', error_code=400, message="Bad Request"), 400

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', error_code=413, message="File too large (max 16MB)"), 413

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', error_code=500, message="Internal Server Error"), 500

def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('index'))
    return wrapper

# Utility functions
def generate_filename(extension):
    """Generate a secure random filename with given extension."""
    if extension.lower() not in app.config['ALLOWED_EXTENSIONS']:
        raise ValueError("Unsupported file extension")
    return f"{uuid.uuid4().hex}.{extension.lower()}"

def validate_key(key):
    """Validate the encryption key meets minimum requirements."""
    if not key or len(key) < 8:
        raise ValueError("Encryption key must be at least 8 characters long")
    return True

def scan_for_malware(file):
    """Perform basic malware scanning on uploaded files."""
    try:
        file.seek(0)
        file_content = file.read(1024 * 1024)  # Read first 1MB for scanning
        
        # Check for common malicious patterns
        malicious_patterns = [
            br'<\?php', br'<script', br'eval\(', br'base64_decode\(', 
            br'document\.write', br'window\.location', br'System\.'
        ]
        
        if any(re.search(pattern, file_content, re.IGNORECASE) for pattern in malicious_patterns):
            raise ValueError("Malicious content detected in file")
            
        file.seek(0)
        return True
    except Exception as e:
        raise ValueError(f"Malware scan failed: {str(e)}")

def validate_image(file):
    """Comprehensive image validation."""
    try:
        # Check MIME type
        if not file.content_type or not any(file.content_type.startswith(f'image/{ext}') for ext in app.config['ALLOWED_EXTENSIONS']):
            raise ValueError("Unsupported image format. Please upload JPEG, PNG, or GIF.")

        # Verify file signature
        file.seek(0)
        file_signature = magic.from_buffer(file.read(2048), mime=True)
        if not file_signature or not any(file_signature == f'image/{ext}' for ext in app.config['ALLOWED_EXTENSIONS']):
            raise ValueError(f"Invalid file signature: {file_signature}")

        # Verify with PIL
        try:
            img = Image.open(file)
            img.verify()  # Verify image integrity
            img.close()
            
            # Check dimensions
            img = Image.open(file)  # Reopen after verify
            width, height = img.size
            if width > app.config['MAX_IMAGE_DIMENSION'] or height > app.config['MAX_IMAGE_DIMENSION']:
                raise ValueError(f"Image dimensions too large. Max allowed is {app.config['MAX_IMAGE_DIMENSION']}x{app.config['MAX_IMAGE_DIMENSION']} pixels.")
                
            return True
        except (UnidentifiedImageError, IOError) as e:
            raise ValueError("Invalid or corrupted image file")
        finally:
            file.seek(0)
    except Exception as e:
        raise ValueError(str(e))

def compress_image(image):
    """Compress image while maintaining quality."""
    try:
        img = Image.open(image)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        img_io = BytesIO()
        img.save(img_io, 'JPEG', quality=app.config['COMPRESSION_QUALITY'])
        img_io.seek(0)
        return img_io
    except Exception as e:
        raise ValueError(f"Image compression failed: {str(e)}")

def encrypt_image(image_data, key):
    """Encrypt image data using AES-256-CBC."""
    try:
        # Ensure key is properly padded for AES-256
        key = pad(key.encode(), AES.block_size)[:app.config['AES_KEY_SIZE']]
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(image_data, AES.block_size))
        return encrypted_data
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_image(encrypted_data, key):
    """Decrypt image data using AES-256-CBC."""
    try:
        if len(encrypted_data) <= AES.block_size:
            raise ValueError("Invalid encrypted data length")
            
        key = pad(key.encode(), AES.block_size)[:app.config['AES_KEY_SIZE']]
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    except (ValueError, KeyError) as e:
        raise ValueError("Invalid key or corrupted data")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# Route handlers
@app.route('/')
def index():
    return render_template('index.html', encrypted_image=None, decrypted_image=None)

@app.route('/encrypt', methods=['POST'])
@handle_errors
def encrypt():
    if 'image' not in request.files or not request.files['image'].filename:
        flash("No image file selected", "danger")
        return redirect(url_for('index'))
        
    if 'key' not in request.form or not request.form['key']:
        flash("Encryption key is required", "danger")
        return redirect(url_for('index'))

    image = request.files['image']
    key = request.form['key'].strip()

    try:
        validate_key(key)
        validate_image(image)
        scan_for_malware(image)
        
        compressed_image = compress_image(image)
        image_data = compressed_image.read()
        encrypted_data = encrypt_image(image_data, key)
        
        encrypted_image_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        encrypted_image_data_url = f"data:application/octet-stream;base64,{encrypted_image_base64}"
        
        return render_template('index.html', 
                             encrypted_image=encrypted_image_data_url,
                             key=key,
                             encrypted_image_base64=encrypted_image_base64)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
@handle_errors
def decrypt():
    if 'encrypted_image' not in request.form or not request.form['encrypted_image']:
        flash("No encrypted data provided", "danger")
        return redirect(url_for('index'))
        
    if 'key' not in request.form or not request.form['key']:
        flash("Decryption key is required", "danger")
        return redirect(url_for('index'))

    encrypted_image = request.form['encrypted_image']
    key = request.form['key'].strip()

    try:
        validate_key(key)
        encrypted_data = base64.b64decode(encrypted_image)
        decrypted_data = decrypt_image(encrypted_data, key)
        
        # Save decrypted image to static folder
        filename = generate_filename('jpg')
        decrypted_image_path = os.path.join(app.static_folder, filename)
        
        with open(decrypted_image_path, 'wb') as f:
            f.write(decrypted_data)
            
        decrypted_image_url = url_for('static', filename=filename)
        
        return render_template('index.html', 
                             encrypted_image=encrypted_image,
                             key=key,
                             encrypted_image_base64=encrypted_image,
                             decrypted_image=decrypted_image_url)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.static_folder, exist_ok=True)
    
    # Run the app
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't'))