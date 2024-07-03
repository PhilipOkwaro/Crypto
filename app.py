'''import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify, unhexlify
from Message import send_text_msg
from decouple import config

# Encryption function
def encrypt_message(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return hexlify(encrypted_message).decode()

# Decryption function
def decrypt_message(encrypted_message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(unhexlify(encrypted_message.encode()))
    return decrypted_message.decode("utf-8")

def generate_keys():
    key = RSA.generate(1024)
    st.session_state.private_key = key
    st.session_state.public_key = key.publickey()

def main():
    st.sidebar.title("Options")
    encrypt_option = st.sidebar.checkbox("Encrypt")
    decrypt_option = st.sidebar.checkbox("Decrypt")

    st.title("Encrypt / Decrypt Text")

    if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
        st.session_state.private_key = None
        st.session_state.public_key = None

    if st.button("Generate RSA Key Pair"):
        with st.spinner("Generating RSA Key Pair..."):
            generate_keys()
            st.success("RSA Key Pair generated!")
            st.error(
                "This is a security risk of exposing the private key. Do not expose it to anyone, this is just a demo")
            st.code(st.session_state.private_key.export_key().decode())

    if st.session_state.public_key:
        st.write("Public Key:")
        st.code(st.session_state.public_key.export_key().decode())

    with st.form("cipher_form"):
        text = st.text_area("Enter text here:")
        submit = st.form_submit_button("Submit")

        if submit:
            if encrypt_option and not decrypt_option:
                if st.session_state.public_key:
                    with st.spinner("Encrypting text..."):
                        result = encrypt_message(text, st.session_state.public_key)
                        st.warning(
                            "This will be sent as a text message. This is just a demo")
                        st.write("Encrypted text:")
                        st.code(result)
                    with st.spinner("Sending text message..."):
                        send_text_msg(destination=config("FROM_PHONE_NUMBER"), msg=f"Public Key: {st.session_state.public_key.export_key().decode()}\nEncrypted Message: {result}")
                else:
                    st.error("Please generate the RSA key pair first.")
            elif decrypt_option and not encrypt_option:
                if st.session_state.private_key:
                    try:
                        result = decrypt_message(text, st.session_state.private_key)
                        st.write("Decrypted text:")
                        st.code(result)
                    except (ValueError, TypeError):
                        st.error("Invalid encrypted text for decryption. Please ensure it is correct.")
                else:
                    st.error("Please generate the RSA key pair first.")
            else:
                st.error("Please select either Encrypt or Decrypt, not both or neither.")

if __name__ == "__main__":
    main()'''

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify
from Message import send_text_msg
from decouple import config
import base64

# Encryption function
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# Decryption function
def decrypt_message(encrypted_message, key):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def generate_key():
    key = get_random_bytes(16)  # AES-128
    st.session_state.key = key

def main():
    st.title("🔐 Encrypt / Decrypt Text Application")

    tabs = st.tabs(["🏷 Key Management", "🔒 Encryption", "🔓 Decryption"])

    with tabs[0]:
        st.header("Key Management")

        if 'key' not in st.session_state:
            st.session_state.key = None

        if st.button("Generate AES Key"):
            with st.spinner("Generating AES Key..."):
                generate_key()
                st.success("AES Key generated!")
                st.error(
                    "This is a security risk of exposing the key. Do not expose it to anyone, this is just a demo")
                st.code(base64.b64encode(st.session_state.key).decode('utf-8'))

        if st.session_state.key:
            st.write("Key:")
            st.code(base64.b64encode(st.session_state.key).decode('utf-8'))

    with tabs[1]:
        st.header("Encryption")

        if st.session_state.key:
            with st.form("encryption_form"):
                text = st.text_area("Enter text to encrypt:")
                submit = st.form_submit_button("Encrypt")

                if submit:
                    with st.spinner("Encrypting text..."):
                        encrypted_text = encrypt_message(text, st.session_state.key)
                        st.success("Text encrypted successfully!")
                        st.code(encrypted_text)

                    with st.spinner("Sending encrypted text message..."):
                        send_text_msg(destination=config("FROM_PHONE_NUMBER"), msg=f"Key: {base64.b64encode(st.session_state.key).decode('utf-8')}\nEncrypted Message: {encrypted_text}")
                        st.success("Encrypted text message sent!")
        else:
            st.warning("Please generate the AES key first in the Key Management tab.")

    with tabs[2]:
        st.header("Decryption")

        if st.session_state.key:
            with st.form("decryption_form"):
                encrypted_text = st.text_area("Enter text to decrypt:")
                submit = st.form_submit_button("Decrypt")

                if submit:
                    try:
                        with st.spinner("Decrypting text..."):
                            decrypted_text = decrypt_message(encrypted_text, st.session_state.key)
                            st.success("Text decrypted successfully!")
                            st.code(decrypted_text)
                    except (ValueError, TypeError):
                        st.error("Invalid encrypted text for decryption. Please ensure it is correct.")
        else:
            st.warning("Please generate the AES key first in the Key Management tab.")

if __name__ == "__main__":
    main()




