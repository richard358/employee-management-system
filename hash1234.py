import bcrypt
print(bcrypt.hashpw("1234".encode('utf-8'), bcrypt.gensalt()).decode())
