import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Utility padding functions ---
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

# --- AES Encryption ---
def encrypt_message(message):
    key = get_random_bytes(16)  # 128-bit AES key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode()))
    return key, cipher.iv, ct_bytes

# --- Steganography (LSB) ---
def embed_data(image_path, output_path, data_bytes):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Image not found: {image_path}")
        
    flat = img.flatten()

    bits = ''.join([format(byte, '08b') for byte in data_bytes])
    if len(bits) > len(flat):
        raise ValueError("Message too large for the image!")

    for i, bit in enumerate(bits):
        flat[i] = (int(flat[i]) & 0xFE) | int(bit)

    stego = flat.reshape(img.shape)
    cv2.imwrite(output_path, stego)

# --- Encode (Main) ---
def encode(image_path, output_path, secret_message):
    key, iv, ciphertext = encrypt_message(secret_message)

    payload = len(key).to_bytes(2, 'big') + key
    payload += len(iv).to_bytes(2, 'big') + iv
    payload += len(ciphertext).to_bytes(4, 'big') + ciphertext

    embed_data(image_path, output_path, payload)
    print("Message embedded successfully into", output_path)

if __name__ == "__main__":
    encode("test1.png", "stego.png", "TMR WE HAVE SUBMISSION EW")
