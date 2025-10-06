from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from secure_chat import SecureNRFChat
import threading

# ------------------ Configuration des pipes ------------------
pipe_write = [0xE1, 0xF0, 0xF0, 0xF0, 0xF0]  # Inverser sur le second Pi
pipe_read  = [0xD2, 0xF0, 0xF0, 0xF0, 0xF0]

# ------------------ Initialisation chat ------------------
chat = SecureNRFChat(pipe_write, pipe_read)

# Liste pour stocker les messages à afficher
messages = []

# ------------------ Serveur Flask ------------------
app = Flask(__name__)
socketio = SocketIO(app)

@app.route("/")
def index():
    return render_template("chat.html", messages=messages)

# Quand un client envoie un message via WebSocket
@socketio.on("send_message")
def handle_send_message(data):
    text = data.get("message")
    if text:
        chat.send(text)
        message = f"Moi: {text}"
        messages.append(message)
        emit("new_message", message, broadcast=True)  # broadcast = tous les clients

# Callback de réception depuis SecureNRFChat
def receive_callback(text):
    message = f"Autre: {text}"
    messages.append(message)
    socketio.emit("new_message", message, broadcast=True)

chat.on_receive = receive_callback

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
