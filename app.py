
from flask import Flask, render_template, request, send_file 
from werkzeug.utils import secure_filename
from io import BytesIO
from encode import encode
from decode import decode
import os


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure uploads folder exists
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
                    output_filename = "encoded_" + filename
                    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

                    encode(filepath, output_path, message)

                    return send_file(
                        output_path,
                        as_attachment=True,
                        download_name="encoded.png",
                        mimetype="image/png"
                    )
            elif action == "decode":
                try:
                    secret_message = decode(filepath)
                    decoded_message = secret_message if secret_message else "No hidden message found."
                except Exception as e:
                    decoded_message = f"Decoding failed: {str(e)}"

    return render_template("index.html", decoded_message=decoded_message)
  

if __name__ == "__main__":
    app.run(debug=True)
