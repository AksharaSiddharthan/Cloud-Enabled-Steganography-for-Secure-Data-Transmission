# from flask import Flask, render_template, request, send_file, jsonify
# import cv2, os, numpy as np
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from werkzeug.utils import secure_filename

# app = Flask(__name__, static_folder='static', template_folder='templates')
# UPLOAD_FOLDER = "uploads"
# OUTPUT_FOLDER = "outputs"
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# # ---------------------- AES + Stego Helpers ----------------------
# def pad(data):
#     pad_len = 16 - (len(data) % 16)
#     return data + bytes([pad_len]) * pad_len

# def unpad(data):
#     pad_len = data[-1]
#     return data[:-pad_len]

# def encrypt_message(message):
#     key = get_random_bytes(16)
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(message.encode()))
#     return key, cipher.iv, ct_bytes

# def decrypt_message(key, iv, ciphertext):
#     cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex(iv))
#     pt = unpad(cipher.decrypt(ciphertext))
#     return pt.decode('utf-8')

# def embed_data(image_path, output_path, data_bytes):
#     img = cv2.imread(image_path)
#     if img is None:
#         raise FileNotFoundError("Invalid image file.")
#     flat = img.flatten()
#     bits = ''.join([format(byte, '08b') for byte in data_bytes])
#     if len(bits) > len(flat):
#         raise ValueError("Message too large for this image!")
#     for i, bit in enumerate(bits):
#         flat[i] = (int(flat[i]) & 0xFE) | int(bit)
#     stego = flat.reshape(img.shape)
#     cv2.imwrite(output_path, stego)

# def extract_data(image_path):
#     img = cv2.imread(image_path)
#     if img is None:
#         raise FileNotFoundError("Invalid image file.")
#     flat = img.flatten()
#     bits = ''.join([str(int(pix) & 1) for pix in flat])
#     data_bytes = bytearray()
#     for i in range(0, len(bits), 8):
#         byte = bits[i:i+8]
#         if len(byte) == 8:
#             data_bytes.append(int(byte, 2))
#     return bytes(data_bytes)

# def encode_image(image_path, output_path, message):
#     key, iv, ciphertext = encrypt_message(message)
#     payload = len(key).to_bytes(2,'big') + key + len(iv).to_bytes(2,'big') + iv
#     payload += len(ciphertext).to_bytes(4,'big') + ciphertext
#     embed_data(image_path, output_path, payload)
#     return key.hex(), iv.hex()

# def decode_image(image_path):
#     data = extract_data(image_path)
#     try:
#         idx = 0
#         key_len = int.from_bytes(data[idx:idx+2], 'big'); idx += 2
#         key = data[idx:idx+key_len]; idx += key_len
#         iv_len = int.from_bytes(data[idx:idx+2], 'big'); idx += 2
#         iv = data[idx:idx+iv_len]; idx += iv_len
#         ct_len = int.from_bytes(data[idx:idx+4], 'big'); idx += 4
#         ciphertext = data[idx:idx+ct_len]
#         cipher = AES.new(key, AES.MODE_CBC, iv)
#         message = unpad(cipher.decrypt(ciphertext)).decode()
#         return message
#     except Exception:
#         raise ValueError("There appears to be no encrypted message in this image.")

# # ---------------------- API Routes ----------------------
# @app.route("/")
# def home():
#     return render_template("index.html")

# @app.route("/encode", methods=["POST"])
# def encode_route():
#     file = request.files.get("image")
#     message = request.form.get("message", "")
#     if not file or not message:
#         return jsonify({"error": "Please upload an image and enter a message."}), 400
#     filename = secure_filename(file.filename)
#     input_path = os.path.join(UPLOAD_FOLDER, filename)
#     output_path = os.path.join(OUTPUT_FOLDER, "stego_" + filename)
#     file.save(input_path)
#     try:
#         key, iv = encode_image(input_path, output_path, message)
#         return jsonify({
#             "success": True,
#             "download": f"/download/stego_{filename}",
#             "key": key,
#             "iv": iv
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route("/decode", methods=["POST"])
# def decode_route():
#     file = request.files.get("image")
#     if not file:
#         return jsonify({"error": "Please upload a stego image."}), 400
#     filename = secure_filename(file.filename)
#     input_path = os.path.join(UPLOAD_FOLDER, filename)
#     file.save(input_path)
#     try:
#         message = decode_image(input_path)
#         return jsonify({"success": True, "message": message})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route("/download/<filename>")
# def download(filename):
#     return send_file(os.path.join(OUTPUT_FOLDER, filename), as_attachment=True)

# if __name__ == "__main__":
#     app.run(debug=True)




from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image

import stegano

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure uploads folder exists
import os
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    encoded_image = None
    decoded_message = None

    if request.method == "POST":
        action = request.form.get("action")
        image_file = request.files.get("image")

        if image_file:
            filename = secure_filename(image_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(filepath)

            if action == "encode":
                message = request.form.get("message")
                if message:
                    # Encode message into image
                    from stegano import lsb
                    secret = lsb.hide(filepath, message)
                    output = BytesIO()
                    secret.save(output, format="PNG")
                    output.seek(0)
                    return send_file(output, as_attachment=True, download_name="encoded.png", mimetype="image/png")
            elif action == "decode":
                # Decode message from image
                from stegano import lsb
                secret_message = lsb.reveal(filepath)
                decoded_message = secret_message if secret_message else "No hidden message found."

    return render_template("index.html", decoded_message=decoded_message)
  

if __name__ == "__main__":
    app.run(debug=True)
