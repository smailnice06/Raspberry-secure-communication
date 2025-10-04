from flask import Flask, render_template, request, redirect, url_for
from secure_chat import SecureNRFChat
import threading

# ------------------ Configuration des pipes ------------------
pipe_write = [0xE1, 0xF0, 0xF0, 0xF0, 0xF0]  # Inverser sur le second Pi
pipe_read  = [0xD2, 0xF0, 0xF0, 0xF0, 0xF0]

# ------------------ Initialisation chat ------------------
chat = SecureNRFChat(pipe_write, pipe_read)

# Liste pour stocker les messages à afficher
messages = []

# Callback pour réception depuis SecureNRFChat
def receive_callback(text):
    messages.append(f"Autre: {text}")

chat.on_receive = receive_callback

# ------------------ Serveur Flask ------------------
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text = request.form.get("message")
        if text:
            chat.send(text)
            messages.append(f"Moi: {text}")
        return redirect(url_for("index"))
    return render_template("chat.html", messages=messages)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
