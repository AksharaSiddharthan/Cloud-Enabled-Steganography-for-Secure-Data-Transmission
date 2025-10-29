# without embedding iv

## pip install opencv-python  # For cv2 (OpenCV)
## pip install numpy  # For numpy
## pip install pycryptodome  # For Crypto.Cipher (AES) and Crypto.Random
## pip install secretsharing  # For secretsharing

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from hashlib import sha256

# ----------- UTILITY PAD FUNCTIONS -----------
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

# ----------- ADAPTIVE CHANNEL SELECTOR -----------
def adaptive_lsb_indices(img_shape, data_len):
    h, w, c = img_shape
    total_pixels = h * w
    indices = []
    for i in range(data_len):
        pixel_idx = i % total_pixels
        channel_idx = (i // total_pixels) % c
        indices.append((pixel_idx // w, pixel_idx % w, channel_idx))
    return indices


# ----------- AES ENCRYPT & SHAMIR SPLIT (IV not embedded) -----------
def encrypt_and_share(message: str, n_shares=3, k_thresh=2):
    """Encrypts the message with AES, then splits AES key into shares using Shamir."""
    if k_thresh > n_shares:
        raise ValueError("Threshold (k_thresh) must be <= total number of shares.")

    key = get_random_bytes(16)  # 128-bit AES key
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode()))
    iv = cipher.iv
    hash_digest = sha256(message.encode()).digest()

    # Shamir split — returns list of (index, share_bytes)
    shares = Shamir.split(k_thresh, n_shares, key)
    return shares, iv, ciphertext, hash_digest

# ----------- EMBED DATA IN IMAGE USING ADAPTIVE LSB (no IV in payload) -----------
def embed_data_adaptive(image_path, output_path, shares, ciphertext, hash_digest):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Image not found: {image_path}")
    
    #h, w, c = img.shape
    payload = b''

    # Encode shares
    for idx, share_bytes in shares:
        payload += idx.to_bytes(1, "big")  # store share index
        payload += len(share_bytes).to_bytes(2, "big") + share_bytes

    # Append ciphertext and hash
    payload += len(ciphertext).to_bytes(4, "big") + ciphertext
    payload += len(hash_digest).to_bytes(2, "big") + hash_digest

    bits = "".join(format(byte, "08b") for byte in payload)
    indices = adaptive_lsb_indices(img.shape, len(bits))

    for i, bit in enumerate(bits):
        x, y, ch = indices[i]
        img[x, y, ch] = (int(img[x, y, ch]) & 0xFE) | int(bit)

    cv2.imwrite(output_path, img)

# ----------- EXTRACT DATA FROM IMAGE ADAPTIVELY (no IV in payload) -----------
def extract_data_adaptive(stego_path, shares_n):
    img = cv2.imread(stego_path)
    if img is None:
        raise FileNotFoundError(f"Stego image not found: {stego_path}")

    #h, w, c = img.shape
    max_len = 4096  # Sufficiently large for most realistic payloads
    indices = adaptive_lsb_indices(img.shape, max_len*8)
    bits = [str(img[x, y, ch] & 1) for (x, y, ch) in indices]

    data_bytes = [int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8)]
    data = bytes(data_bytes)
    # Extract shares
    offset = 0
    shares = []
    # Extract shares
    for _ in range(shares_n):
        idx = data[offset]
        offset += 1
        shlen = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        share_bytes = data[offset:offset + shlen]
        shares.append((idx, share_bytes))
        offset += shlen

    ct_len = int.from_bytes(data[offset:offset+4], 'big')
    offset += 4
    ciphertext = data[offset:offset+ct_len]
    offset += ct_len

    hashlen = int.from_bytes(data[offset:offset+2], 'big')
    offset += 2
    hash_digest = data[offset:offset+hashlen]
    
    return shares, ciphertext, hash_digest

# ----------- DECRYPT AND VERIFY -----------
def decrypt_and_verify(shares, k_thresh, iv, ciphertext, hash_digest):
    #Reconstruct AES key from shares, decrypt ciphertext, and verify integrity.
    if len(shares) < k_thresh:
        raise ValueError(f"Not enough shares provided! Need at least {k_thresh}.")
    
    key = Shamir.combine(shares[:k_thresh])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    if sha256(plaintext).digest() != hash_digest:
        raise ValueError("Integrity check failed! The decrypted data is corrupted.")
    return plaintext.decode()

# ----------- MAIN ENCODE/DECODE FUNCTIONS -----------
def encode(image_path, output_path, secret_message, n_shares=3, k_thresh=2):
    shares, iv, ciphertext, hash_digest = encrypt_and_share(secret_message, n_shares, k_thresh)
    embed_data_adaptive(image_path, output_path, shares, ciphertext, hash_digest)
    print("Message embedded successfully (with threshold key sharing) into", output_path)
    print("Share the following IV (hex) securely with authorized recipients (not embedded):", iv.hex())

def decode(stego_path, iv_hex, shares_n=3, k_thresh=2):
    shares, ciphertext, hash_digest = extract_data_adaptive(stego_path, shares_n)
    iv = bytes.fromhex(iv_hex)
    message = decrypt_and_verify(shares, k_thresh, iv, ciphertext, hash_digest)
    print("Decoded message:", message)

# ----------- EXAMPLE USAGE -----------
if __name__ == "__main__":
    # To encode
    encode("test_img1.png", "stego_img1.png", "Confidential: Group access message", n_shares=4, k_thresh=3)
    # To decode
    # Replace <iv_hex> with the hex string printed during encode
    #decode("stego_img1.png", "2d2b918646a10fb8ea40a27c550eb131", shares_n=4, k_thresh=3)
