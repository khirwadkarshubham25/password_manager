from cryptography.fernet import Fernet


def create_key():
    key = Fernet.generate_key()

    with open("../../secret.key", "wb") as f:
        f.write(key)


create_key()