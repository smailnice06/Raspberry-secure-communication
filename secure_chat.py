# secure_chat.py
import spidev
import time
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class SecureNRFChat:
    def __init__(self, pipe_write, pipe_read, ce_pin=22, spi_bus=0, spi_device=0):
        # -------- IMPORTS LOCAUX ----------
        import pigpio
        from lib_nrf24 import NRF24

        self.radio = None
        self.simulation_mode = False

        # -------- INITIALISATION RADIO ----------
        try:
            pi = pigpio.pi()
            if not pi.connected:
                raise RuntimeError("Le démon pigpiod n'est pas lancé. Démarre-le avec : sudo systemctl start pigpiod")

            spi = spidev.SpiDev()
            spi.open(spi_bus, spi_device)
            spi.max_speed_hz = 4000000

            self.radio = NRF24(pi, spi)
            self.radio.begin(ce_pin, spi_device)
            self.radio.set_retries(5, 15)
            self.radio.set_payload_size(32)
            self.radio.set_channel(0x76)
            self.radio.set_data_rate(NRF24.BR_1MBPS)
            self.radio.set_pa_level(NRF24.PA_LOW)
            self.radio.open_writing_pipe(pipe_write)
            self.radio.open_reading_pipe(1, pipe_read)
            self.radio.start_listening()

        except (FileNotFoundError, RuntimeError, OSError):
            print("[AVERTISSEMENT] Aucun module NRF24 détecté — mode simulation activé.")
            self.radio = None
            self.simulation_mode = True

        # -------- VARIABLES DE COMMUNICATION ----------
        self.seq_send = 0
        self.ack_timeout = 0.5
        self.key_exchange_done = False
        self.remote_public_key = None
        self.fragments = []
        self.on_receive = None  # Callback pour messages reçus

        # -------- GÉNÉRATION CLÉS RSA ----------
        print("[INFO] Génération des clés RSA (cela peut prendre quelques secondes)...")
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("[INFO] Clés RSA générées avec succès.")

        # -------- THREAD DE RÉCEPTION ----------
        self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receiver_thread.start()

        # -------- ÉCHANGE DE CLÉS ----------
        print("[INFO] Envoi de la clé publique locale...")
        self._send_key_fragmented()
        print("[INFO] Clé publique envoyée, en attente de la clé distante...")

        if self.simulation_mode:
            print("[SIMULATION] Mode sans radio : échange de clé simulé.")
            self.key_exchange_done = True
        else:
            while not self.key_exchange_done:
                time.sleep(0.1)

        print("[INFO] Clé publique distante reçue ! Communication sécurisée établie.\n")

    # -------- FONCTIONS INTERNES ----------
    def _send_key_fragmented(self):
        if self.radio is None:
            print("[SIMULATION] Envoi de clé publique ignoré (pas de radio).")
            return

        max_payload = 30
        for i in range(0, len(self.pub_bytes), max_payload):
            chunk = self.pub_bytes[i:i + max_payload]
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
        if self.radio is None:
            return
        ack_packet = [seq, 0xFF] + [0] * 30
        self.radio.stopListening()
        self.radio.write(ack_packet)
        self.radio.startListening()

    def _receive_messages(self):
        if self.radio is None:
            return  # pas de réception en mode simulation

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
                                self.on_receive(text)
                        except Exception as e:
                            print(f"Erreur déchiffrement: {e}")
            time.sleep(0.01)

    # -------- FONCTIONS PUBLIQUES ----------
    def encrypt(self, message: str) -> bytes:
        if not self.remote_public_key and not self.simulation_mode:
            raise ValueError("Pas de clé publique distante.")
        if self.simulation_mode:
            return message.encode('utf-8')
        return self.remote_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )

    def decrypt(self, ciphertext: bytes) -> str:
        if self.simulation_mode:
            return ciphertext.decode('utf-8')
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        ).decode('utf-8')

    def send(self, message: str):
        if self.radio is None:
            print(f"[SIMULATION] Message simulé : {message}")
            return

        data_bytes = self.encrypt(message)
        max_payload = 30
        packets = []
        for i in range(0, len(data_bytes), max_payload):
            chunk = data_bytes[i:i + max_payload]
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
