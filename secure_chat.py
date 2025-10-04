# secure_chat.py
from nrf24 import NRF24
import spidev
import time
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class SecureNRFChat:
    def __init__(self, pipe_write, pipe_read, ce_pin=22, spi_bus=0, spi_device=0):
    # -------- CONFIGURATION RADIO ----------
    spi = spidev.SpiDev()
    spi.open(spi_bus, spi_device)          # bus=0, device=0
    spi.max_speed_hz = 4000000             # 4 MHz
    self.radio = NRF24(spi, ce=ce_pin)     # CE = GPIO22 par défaut

    # Config radio
    self.radio.setRetries(5, 15)
    self.radio.setPayloadSize(32)
    self.radio.setChannel(0x76)
    self.radio.setDataRate(NRF24.BR_1MBPS)
    self.radio.setPALevel(NRF24.PA_LOW)
    self.radio.openWritingPipe(pipe_write)
    self.radio.openReadingPipe(1, pipe_read)
    self.radio.startListening()

    # -------- VARIABLES ----------
    self.seq_send = 0
    self.ack_timeout = 0.5
    self.key_exchange_done = False
    self.remote_public_key = None
    self.fragments = []
    self.on_receive = None  # Callback pour messages reçus

    # -------- GENERATION CLÉS RSA ----------
    self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    self.public_key = self.private_key.public_key()
    self.pub_bytes = self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # -------- THREAD DE RECEPTION ----------
    self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
    self.receiver_thread.start()

    # -------- ECHANGE DE CLÉS ----------
    print("Envoi de ma clé publique...")
    self._send_key_fragmented()
    print("Clé publique envoyée, en attente de la clé de l'autre Pi...")
    while not self.key_exchange_done:
        time.sleep(0.1)
    print("Clé publique distante reçue ! Chat prêt.\n")


    # -------- FONCTIONS INTERNES ----------
    def _send_key_fragmented(self):
        max_payload = 30
        for i in range(0, len(self.pub_bytes), max_payload):
            chunk = self.pub_bytes[i:i+max_payload]
            flags = 0x01 if i + max_payload >= len(self.pub_bytes) else 0x00
            packet = [self.seq_send, flags] + list(chunk)
            while len(packet) < 32:
                packet.append(0)
            success = False
            while not success:
                self.radio.stopListening()
                success = self.radio.write(packet)
                self.radio.startListening()
                time.sleep(0.05)
            self.seq_send = (self.seq_send + 1) % 256

    def _send_ack(self, seq):
        ack_packet = [seq, 0xFF] + [0]*30
        self.radio.stopListening()
        self.radio.write(ack_packet)
        self.radio.startListening()

    def _receive_messages(self):
        while True:
            if self.radio.available(0):
                received = []
                self.radio.read(received, self.radio.getDynamicPayloadSize())
                seq = received[0]
                flags = received[1]

                if flags == 0xFF:  # ACK
                    continue

                self._send_ack(seq)
                self.fragments.append(received[2:])

                if flags == 0x01:
                    total_bytes = b''.join(bytes(frag).rstrip(b'\x00') for frag in self.fragments)
                    self.fragments = []

                    if not self.key_exchange_done:
                        try:
                            self.remote_public_key = serialization.load_pem_public_key(total_bytes)
                            self.key_exchange_done = True
                        except Exception as e:
                            print(f"Erreur clé publique : {e}")
                    else:
                        try:
                            text = self.decrypt(total_bytes)
                            if self.on_receive:
                                self.on_receive(text)  # Callback vers Flask ou console
                        except Exception as e:
                            print(f"Erreur déchiffrement: {e}")
            time.sleep(0.01)

    # -------- FONCTIONS PUBLIQUES ----------
    def encrypt(self, message: str) -> bytes:
        return self.remote_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )

    def decrypt(self, ciphertext: bytes) -> str:
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        ).decode('utf-8')

    def send(self, message: str):
        data_bytes = self.encrypt(message)
        max_payload = 30
        packets = []
        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i+max_payload]
            flags = 0x01 if i + max_payload >= len(data_bytes) else 0x00
            packet = [self.seq_send, flags] + list(chunk)
            while len(packet) < 32:
                packet.append(0)
            packets.append(packet)

        for pkt in packets:
            success = False
            attempts = 0
            while not success and attempts < 5:
                self.radio.stopListening()
                success = self.radio.write(pkt)
                self.radio.startListening()

                start = time.time()
                ack_received = False
                while time.time() - start < self.ack_timeout:
                    if self.radio.available(0):
                        received = []
                        self.radio.read(received, self.radio.getDynamicPayloadSize())
                        if received[0] == self.seq_send and received[1] == 0xFF:
                            ack_received = True
                            break
                    time.sleep(0.01)
                if ack_received:
                    success = True
                else:
                    attempts += 1
                    time.sleep(0.05)
            if not success:
                print(f"Erreur: paquet seq {self.seq_send} perdu après 5 tentatives")
        self.seq_send = (self.seq_send + 1) % 256
