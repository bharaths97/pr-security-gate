import jwt


def parse_token(token):
    return jwt.decode(token, "demo-key", options={"verify_signature": False})
