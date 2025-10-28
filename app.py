
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
