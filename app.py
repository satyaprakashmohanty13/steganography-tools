import os
import io
from datetime import datetime, timedelta
from flask import Flask, request, render_template, send_file, flash, redirect, url_for, session
from PIL import Image

app = Flask(__name__)
# Secret key for signing session cookies. Override via environment variable in production.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production")
# Optional: limit upload size (e.g., 16 MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def initialize_user():
    """
    Initialize credits and last_visit in session for a new user.
    New users start with 5 credits.
    """
    if 'credits' not in session:
        session['credits'] = 5
        session['last_visit'] = datetime.utcnow().isoformat()

def check_daily_credit():
    """
    If at least 24 hours have passed since last_visit, grant 1 credit and update last_visit.
    """
    last_visit_str = session.get('last_visit')
    try:
        last_visit = datetime.fromisoformat(last_visit_str)
    except Exception:
        # If parsing fails, reset last_visit to now without granting extra credit immediately
        last_visit = datetime.utcnow()
        session['last_visit'] = last_visit.isoformat()
        return

    now = datetime.utcnow()
    if now - last_visit >= timedelta(days=1):
        # Grant exactly 1 credit on each visit after 24h
        session['credits'] = session.get('credits', 0) + 1
        session['last_visit'] = now.isoformat()

def encode_image(image: Image.Image, message: str) -> Image.Image:
    """
    Encode `message` into `image` via LSB steganography.
    """
    img = image.convert('RGB')
    width, height = img.size
    max_bits = width * height * 3
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    total_bits_needed = 32 + message_length * 8
    if total_bits_needed > max_bits:
        raise ValueError(f"Message too large to encode. Max bytes: {(max_bits - 32)//8}, got {message_length}")
    # Build bits: 32-bit length prefix + message bits
    length_bits = [int(bit) for bit in format(message_length, '032b')]
    msg_bits = []
    for b in message_bytes:
        bits8 = format(b, '08b')
        msg_bits.extend(int(x) for x in bits8)
    bits_to_hide = length_bits + msg_bits

    pixels = list(img.getdata())
    new_pixels = []
    bit_idx = 0
    total_bits = len(bits_to_hide)
    for pixel in pixels:
        r, g, b = pixel
        new_rgb = []
        for color in (r, g, b):
            if bit_idx < total_bits:
                new_color = (color & ~1) | bits_to_hide[bit_idx]
                bit_idx += 1
            else:
                new_color = color
            new_rgb.append(new_color)
        new_pixels.append(tuple(new_rgb))
    stego = Image.new('RGB', (width, height))
    stego.putdata(new_pixels)
    return stego

def decode_image(image: Image.Image) -> str:
    """
    Decode hidden message from `image`.
    """
    img = image.convert('RGB')
    pixels = list(img.getdata())
    bits = []
    for pixel in pixels:
        for color in pixel:
            bits.append(color & 1)
    if len(bits) < 32:
        raise ValueError("Image too small or no hidden data.")
    length_bits = bits[:32]
    message_length = int(''.join(str(bit) for bit in length_bits), 2)
    total_bits = 32 + message_length * 8
    if total_bits > len(bits):
        raise ValueError("Encoded message length exceeds available data; possibly no valid hidden message.")
    msg_bits = bits[32:total_bits]
    message_bytes = bytearray()
    for i in range(0, len(msg_bits), 8):
        byte = msg_bits[i:i+8]
        byte_val = int(''.join(str(bit) for bit in byte), 2)
        message_bytes.append(byte_val)
    try:
        return message_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return message_bytes.decode('utf-8', errors='ignore')

@app.route('/', methods=['GET'])
def index():
    initialize_user()
    check_daily_credit()
    credits = session.get('credits', 0)
    # Compute next credit time = last_visit + 24h
    try:
        last_visit = datetime.fromisoformat(session.get('last_visit'))
    except Exception:
        last_visit = datetime.utcnow()
        session['last_visit'] = last_visit.isoformat()
    next_credit_time = last_visit + timedelta(days=1)
    # Format as UTC ISO with 'Z' so JS Date parses as UTC
    next_credit_time_str = next_credit_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return render_template('index.html', credits=credits, next_credit_time=next_credit_time_str)

@app.route('/encode', methods=['POST'])
def encode_route():
    initialize_user()
    check_daily_credit()
    if session.get('credits', 0) < 3:
        flash("You need at least 3 credits to encode an image.", "error")
        return redirect(url_for('index'))

    if 'image' not in request.files or request.files['image'].filename == '':
        flash("No image file selected for encoding.", "error")
        return redirect(url_for('index'))
    message = request.form.get('message', '').strip()
    if not message:
        flash("Please provide a message to hide.", "error")
        return redirect(url_for('index'))

    image_file = request.files['image']
    try:
        image = Image.open(image_file.stream)
    except Exception:
        flash("Unable to open uploaded file as an image.", "error")
        return redirect(url_for('index'))

    try:
        stego = encode_image(image, message)
    except ValueError as ve:
        flash(str(ve), "error")
        return redirect(url_for('index'))
    except Exception:
        flash("Unexpected error during encoding.", "error")
        return redirect(url_for('index'))

    # Deduct credits after successful encode
    session['credits'] = session.get('credits', 0) - 3

    # Prepare image to send
    buffer = io.BytesIO()
    stego.save(buffer, format='PNG')
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name='stego.png',
        mimetype='image/png'
    )

@app.route('/decode', methods=['POST'])
def decode_route():
    initialize_user()
    check_daily_credit()
    if session.get('credits', 0) < 3:
        flash("You need at least 3 credits to decode an image.", "error")
        return redirect(url_for('index'))

    if 'image' not in request.files or request.files['image'].filename == '':
        flash("No image file selected for decoding.", "error")
        return redirect(url_for('index'))
    image_file = request.files['image']
    try:
        image = Image.open(image_file.stream)
    except Exception:
        flash("Unable to open uploaded file as an image.", "error")
        return redirect(url_for('index'))

    try:
        hidden_message = decode_image(image)
        flash(f"Decoded message: {hidden_message}", "info")
    except ValueError as ve:
        flash(f"Decoding error: {ve}", "error")
    except Exception:
        flash("An unexpected error occurred during decoding.", "error")

    # Deduct credits after attempting decode (only if decode did not early-return)
    if session.get('credits', 0) >= 3:
        session['credits'] = session.get('credits', 0) - 3
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
