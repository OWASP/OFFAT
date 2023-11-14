import secrets
import string


def generate_random_secret_key_string(length=128):
    # Define the characters allowed in the HTTP header
    characters = string.ascii_letters + string.digits + "-_."

    # Generate a random string of the specified length
    random_string = ''.join(secrets.choice(characters) for _ in range(length))

    return random_string
