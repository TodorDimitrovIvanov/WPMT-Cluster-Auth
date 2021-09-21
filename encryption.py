import base64

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def encrypt(message):
    key = open('temp', 'rb')
    public_key = load_pem_public_key(
        key.read(),
        default_backend())
    result = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    print("Encrypted Message: ", result, "Type: ", type(result))
    return result


def key_to_utf8(s: bytes):
    return str(s, 'utf-8')


def decrypt(message):
    # Here we edit the private key received from the DB
    # And remove the '\n' special characters from it

    #with open('private.txt', 'rb') as file:
    #    cleaned_key = file.read().replace('\n', '')
    key = open('private.txt', 'rb')
    #cleaned_key = key.replace('\n', '')

    #print("Cleaned Key: ", cleaned_key, "Type: ", type(cleaned_key))
    private_key = load_pem_private_key(
        key.read(),
        backend=default_backend(),
        password=None)

    result = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    '''result = private_key.decrypt(
        base64.b64decode(message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )'''
    print("Decrypted Message: ", result, "Type: ", type(result))


if __name__ == '__main__':
    message = input("Message: ")
    encrypted_message = encrypt(message)
    decrypt(encrypted_message)