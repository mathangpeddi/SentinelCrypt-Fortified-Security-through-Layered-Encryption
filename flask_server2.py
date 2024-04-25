from flask import Flask, request, jsonify
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from ecies import encrypt, decrypt, generate_key
import base64
import os
import hmac
import hashlib
import json

app = Flask(__name__)

SECRET_KEY = b'12345'  # Replace with your secret key

# Initialize RSA key pair
rsa_key_pair = RSA.generate(2048)
rsa_public_key = rsa_key_pair.publickey()
rsa_private_key = rsa_key_pair

# Initialize ECC key pair
ecc_private_key = ECC.generate(curve='P-256')
ecc_public_key = ecc_private_key.public_key()

def generate_hmac(data):
    return hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()

def encrypt_and_hash(text, key, iv, algorithm, hash_algorithm):
    if algorithm not in ['AES', 'DES', '3DES', 'RSA', 'ECC']:
        raise ValueError("Invalid encryption algorithm. Please choose 'AES', 'DES', '3DES', 'RSA', or 'ECC'.")

    if hash_algorithm not in ['SHA1', 'SHA256', 'MD5']:
        raise ValueError("Invalid hash algorithm. Please choose 'SHA1' or 'SHA256 or MD5'.")

    if algorithm in ['AES', 'DES', '3DES']:
        if len(iv) != 16 and algorithm == 'AES':
            raise ValueError("IV must be 16 bytes long for AES")
        elif len(iv) != 8 and algorithm in ['DES', '3DES']:
            raise ValueError("IV must be 8 bytes long for DES and 3DES")

        if algorithm == 'AES':
            cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == 'DES':
            cipher_encrypt = DES.new(key, DES.MODE_CBC, iv)
        elif algorithm == '3DES':
            cipher_encrypt = DES3.new(key, DES3.MODE_CBC, iv)
        encrypted_text = cipher_encrypt.encrypt(pad(text.encode(), cipher_encrypt.block_size))
    elif algorithm == 'RSA':
        cipher_encrypt = PKCS1_OAEP.new(rsa_public_key)
        encrypted_text = cipher_encrypt.encrypt(text.encode())
    elif algorithm == 'ECC':
        encrypted_text = encrypt(ecc_public_key, text.encode())

    if hash_algorithm == 'SHA1':
        hasher = SHA1.new()
    elif hash_algorithm == 'SHA256':
        hasher = SHA256.new()
    elif hash_algorithm == 'MD5':
        hasher = hashlib.md5()
    hasher.update(encrypted_text)
    hashed_text = hasher.digest()

    encrypted_text_encoded = base64.b64encode(encrypted_text).decode('utf-8')
    hashed_text_encoded = base64.b64encode(hashed_text).decode('utf-8')

    return encrypted_text_encoded, hashed_text_encoded, key, iv, None, None


def decrypt_text(encrypted_text_encoded, key, iv, algorithm):
    encrypted_text = base64.b64decode(encrypted_text_encoded)

    if algorithm in ['AES', 'DES', '3DES']:
        if algorithm == 'AES':
            cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == 'DES':
            cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
        elif algorithm == '3DES':
            cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_text = unpad(cipher_decrypt.decrypt(encrypted_text), cipher_decrypt.block_size)
    elif algorithm == 'RSA':
        cipher_decrypt = PKCS1_OAEP.new(rsa_private_key)
        decrypted_text = cipher_decrypt.decrypt(encrypted_text)
    elif algorithm == 'ECC':
        decrypted_text = decrypt(ecc_private_key, encrypted_text)

    return decrypted_text.decode()

@app.route('/encrypt_and_hash', methods=['POST'])
def handle_encryption():
    data = request.get_json()

    # Extract the authentication method from the request headers
    auth_method = request.headers.get('Authentication-Method')

    # Verify integrity/authentication based on the selected method
    if auth_method == 'HMAC' or auth_method == 'DSA':
        # Extract the HMAC from the request headers
        client_hmac = request.headers.get('HMAC')

        # Generate HMAC for the received data
        computed_hmac = generate_hmac(json.dumps(data))

        # Compare the HMACs to verify integrity
        if hmac.compare_digest(client_hmac, computed_hmac):
            algorithm = data.get('algorithm')
            hash_algorithm = data.get('hash_algorithm')
            plaintext = data.get('plaintext')

            key = None
            iv = None

            print('algorithm here is ', algorithm)

            if algorithm in ['AES', 'DES', '3DES']:
                key = os.urandom(32) if algorithm == 'AES' else os.urandom(24) if algorithm == '3DES' else os.urandom(8)
                iv = os.urandom(16) if algorithm == 'AES' else os.urandom(8)
            elif algorithm == 'RSA':
                key = rsa_public_key
                # Set IV to empty byte string for RSA
                iv = b''
            elif algorithm == 'ECC':
                key = ecc_private_key
                # Set IV to empty byte string for ECC
                iv = b''

            if key is None:
                return jsonify({"error": "Invalid algorithm specified"}), 400

            encrypted_text, hashed_text, _, _, _, _ = encrypt_and_hash(plaintext, key, iv, algorithm, hash_algorithm)
            decrypted_text = decrypt_text(encrypted_text, key, iv, algorithm)

            # For RSA and ECC, there's no need to return key and iv
            if algorithm in ['RSA', 'ECC']:
                response_data = {
                    'encrypted_text': encrypted_text,
                    'hashed_text': hashed_text,
                    'decrypted_text': decrypted_text,
                    'key':  base64.b64encode(key.export_key()).decode('utf-8'),
                    'private_key': base64.b64encode(rsa_private_key.export_key()).decode('utf-8'),
                    'iv': None
                }
            else:
                response_data = {
                    'encrypted_text': encrypted_text,
                    'hashed_text': hashed_text,
                    'decrypted_text': decrypted_text,
                    'key': base64.b64encode(key).decode('utf-8'),
                    'private_key': None,
                    'iv': base64.b64encode(iv).decode('utf-8')
                }

            return jsonify(response_data)
        else:
            return jsonify({"error": "HMAC verification failed"}), 401
    else:
        return jsonify({"error": "Invalid authentication method"}), 400

if __name__ == '__main__':
    app.run(debug=True)
