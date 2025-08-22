
import hashlib
import random

def hash_password(password):
    # VULNERABLE: Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # VULNERABLE: Using weak SHA1 hash  
    data = str(random.random())
    return hashlib.sha1(data.encode()).hexdigest()

def create_session_id():
    # VULNERABLE: Using predictable random
    return str(random.randint(1000000, 9999999))
