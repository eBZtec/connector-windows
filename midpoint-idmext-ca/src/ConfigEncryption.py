from cryptography.fernet import Fernet

key = Fernet.generate_key()

with open('midpoint-idmext-ca/configuration/secret.key', 'wb') as key_file:
    key_file.write(key)

with open('midpoint-idmext-ca/configuration/config.ini', 'rb') as file:
    file_data = file.read()

fernet = Fernet(key)
encrypted_data = fernet.encrypt(file_data)

with open('midpoint-idmext-ca/configuration/encrypted_config.ini', 'wb') as encrypted_file:
    encrypted_file.write(encrypted_data)
