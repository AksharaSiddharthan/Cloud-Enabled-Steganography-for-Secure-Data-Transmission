import cv2
#import numpy as np
from Crypto.Cipher import AES

# --- Utility ---
def unpad(data):
    return data[:-data[-1]]

# --- AES Decryption ---
def decrypt_message(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext))
    return pt.decode()

# --- Steganography Extraction ---
def extract_data(stego_path, length):
    img = cv2.imread(stego_path)
    flat = img.flatten()

    bits = [str(flat[i] & 1) for i in range(length * 8)]
    data = [int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8)]
    return bytes(data)

# --- Decode (Main) ---
def decode(stego_path):
    # Extract Key Length
    raw = extract_data(stego_path, 2)
    key_len = int.from_bytes(raw, 'big')

    # Extract Key
    raw = extract_data(stego_path, 2 + key_len)
    key = raw[2:]

    # Extract IV Length
    raw2 = extract_data(stego_path, 2 + key_len + 2)
    iv_len = int.from_bytes(raw2[-2:], 'big')

    # Extract IV
    raw3 = extract_data(stego_path, 2 + key_len + 2 + iv_len)
    iv = raw3[-iv_len:]

    # Extract Ciphertext Length
    raw4 = extract_data(stego_path, 2 + key_len + 2 + iv_len + 4)
    ct_len = int.from_bytes(raw4[-4:], 'big')

    # Extract Ciphertext
    total_len = 2 + key_len + 2 + iv_len + 4 + ct_len
    raw5 = extract_data(stego_path, total_len)
    ciphertext = raw5[-ct_len:]

    # Decrypt
    message = decrypt_message(key, iv, ciphertext)
    return message

if __name__ == "__main__":
    decoded_message = decode("test1.png")
    print(" Decoded message:", decoded_message)
