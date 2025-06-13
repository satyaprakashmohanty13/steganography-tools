import os
import io
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from PIL import Image

app = Flask(__name__)
# For flashing messages (e.g., errors); in production, set a secure random key via env var
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_in_production")

def encode_image(image: Image.Image, message: str) -> Image.Image:
    """
    Encode `message` into `image` using LSB steganography.
    Returns a new PIL Image with the hidden message.
    """
    img = image.convert('RGB')
    width, height = img.size
    max_bits = width * height * 3  # total LSBs available
    # Prepare message bytes
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    # We'll store length in first 32 bits, then message bits
    total_bits_needed = 32 + message_length * 8
    if total_bits_needed > max_bits:
        raise ValueError(f"Message too large to encode in this image. Max bytes: {(max_bits - 32)//8}, got {message_length}")
    # Build bits list: first 32 bits of length
    length_bits = [int(bit) for bit in format(message_length, '032b')]
    msg_bits = []
    for byte in message_bytes:
        bits8 = format(byte, '08b')
        msg_bits.extend(int(b) for b in bits8)
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
    # Create new image
    stego = Image.new('RGB', (width, height))
    stego.putdata(new_pixels)
    return stego

def decode_image(image: Image.Image) -> str:
    """
    Decode hidden message from `image`. Returns the extracted string.
    """
    img = image.convert('RGB')
    pixels = list(img.getdata())
    bits = []
    for pixel in pixels:
        for color in pixel:
            bits.append(color & 1)
    # First 32 bits: message length in bytes
    if len(bits) < 32:
        raise ValueError("Image too small or no hidden data.")
    length_bits = bits[:32]
    message_length = int(''.join(str(bit) for bit in length_bits), 2)
    total_bits = 32 + message_length * 8
    if total_bits > len(bits):
        raise ValueError("Encoded message length exceeds available data; possibly no valid hidden message.")
    msg_bits = bits[32:total_bits]
    # Build bytes
    message_bytes = bytearray()
    for i in range(0, len(msg_bits), 8):
        byte = msg_bits[i:i+8]
        byte_val = int(''.join(str(bit) for bit in byte), 2)
        message_bytes.append(byte_val)
    try:
        message = message_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        # fallback to ignore errors
        message = message_bytes.decode('utf-8', errors='ignore')
    return message

@app.route('/', methods=['GET'])
def index():
    # Renders the main page. If a decode result is provided via query params or flash, it will appear.
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode_route():
    if 'image' not in request.files or request.files['image'].filename == '':
        flash("No image file selected for encoding.", "error")
        return redirect(url_for('index'))
    image_file = request.files['image']
    message = request.form.get('message', '')
    if message == '':
        flash("Please provide a message to hide.", "error")
        return redirect(url_for('index'))
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
    # Prepare image for download
    buffer = io.BytesIO()
    stego.save(buffer, format='PNG')
    buffer.seek(0)
    # Send as attachment
    return send_file(
        buffer,
        as_attachment=True,
        download_name='stego.png',
        mimetype='image/png'
    )

@app.route('/decode', methods=['POST'])
def decode_route():
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
    return redirect(url_for('index'))

if __name__ == '__main__':
    # For local development; Render will use gunicorn via Procfile.
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
