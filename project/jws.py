from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend
import json
import base64
import math

class ECKey:
    def __init__(self):
        self.alg = "ES256"
        self.key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.kid = None
    
    def sign(self, msg):
        signature = self.key.sign(msg, ec.ECDSA(hashes.SHA256()))
        public_key = self.key.public_key()
        public_key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        r_bytes = r.to_bytes(32, 'big')
        s_bytes = s.to_bytes(32, 'big')
        return r_bytes + s_bytes
        
    def jwk(self):
        public_numbers = self.key.public_key().public_numbers()
        x = public_numbers.x
        y = public_numbers.y
        x_encoded = base64.urlsafe_b64encode(x.to_bytes(32, 'big')).rstrip(b'=').decode()
        y_encoded = base64.urlsafe_b64encode(y.to_bytes(32, 'big')).rstrip(b'=').decode()
        jwk = {'kty': 'EC', 'crv': 'P-256', 'x': x_encoded, 'y': y_encoded}
        return jwk

class JWS:
    def __init__(self, key):
        self.key = key
    
    def create(self, header: dict, payload: dict):
        if self.key.kid == None:
            header['jwk'] = self.key.jwk()
        else:
            header['kid'] = self.key.kid
        if isinstance(header, dict):
            header = json.dumps(header).encode()
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode()
        header_encoded = base64.urlsafe_b64encode(header).rstrip(b'=')
        payload_encoded = base64.urlsafe_b64encode(payload).rstrip(b'=')
        signature = self.key.sign(header_encoded + b'.' + payload_encoded)
        signature_encoded = base64.urlsafe_b64encode(signature).rstrip(b'=')
        jws = json.dumps({'protected': header_encoded.decode(), 'payload': payload_encoded.decode(), 'signature': signature_encoded.decode()})
        return jws

'''
key = ECKey()
example = "TEST"
signature = key.sign(example.encode())
jwk = key.jwk()
jws = JWS(key)
header = {'alg': 'ES256'}
payload = {'iss': 'joe', 'exp': 1300819380, 'http://example.com/is_root': True}
result = jws.create(header, payload)
print(result)
'''
