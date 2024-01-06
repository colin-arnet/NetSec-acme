import cryptography
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import requests
import json
from jws import JWS, ECKey
import base64
import hashlib
import time

class Client:
    def __init__(self, dir, challenge_type, timeout, retry_interval):
        self.key = ECKey()
        self.session = requests.Session()
        self.session.verify = 'pebble.minica.pem'
        self.dir = self.session.get(dir).json()
        self.order = {}
        self.challgene_types = ['http-01', 'dns-01']
        if challenge_type == 'http01':
            self.challenge_type = 'http-01'
        else:
            self.challenge_type = 'dns-01'
        self.challenges = {}
        self.dns_server = None
        self.timeout = timeout
        self.retry_interval = retry_interval
        self.csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.certificate = None
    
    def create_account(self):
        print("Create Account")
        payload = {'termsOfServiceAgreed': True}
        response = self.make_request(self.dir['newAccount'], payload, {})
        self.key.kid = response.headers['Location']
    
    def put_order(self, domains):
        print("Put Order")
        identifiers = []
        for domain in domains:
            identifier = {'type': 'dns', 'value': domain}
            identifiers.append(identifier)
        payload = {'identifiers': identifiers}
        response = self.make_request(self.dir['newOrder'], payload, {})
        order_url = response.headers['Location']
        self.order = response.json()
        self.order['url'] = order_url

    def get_challenges(self):
        print("Get Challenges")
        challenges = {}
        # iterate through authorizations
        for authorization in self.order['authorizations']:
            # get authorization information
            response = self.make_request(authorization, b'', {}).json()
            identifier = response['identifier']['value']
            if not (identifier in challenges):
                challenges[identifier] = []
            # get challenges and check their type
            temp_challenges = response['challenges']
            for chall in temp_challenges:
                if chall['type'] == self.challenge_type:
                    challenges[identifier].append(chall)
        self.challenges = challenges

    def prove_control(self):
        print("Prove Control")
        for identifier, challenges in self.challenges.items():
            for challenge in challenges:
                print(identifier)
                if challenge['type'] == 'http-01':
                    self.solve_http_challenge(identifier, challenge)
                elif challenge['type'] == 'dns-01':
                    self.solve_dns_challenge(identifier, challenge)
                self.make_request(challenge['url'], {}, {})
                
    
    def solve_http_challenge(self, identifier, challenge):
        print("Solve HTTP")
        token = challenge['token']
        key_authorization = self.compute_key_authorization(token)
        filepath = 'home/.well-known/acme-challenge/' + token
        with open(filepath, 'wb') as f:
            f.write(key_authorization)
    
    def solve_dns_challenge(self, identifier, challenge):
        print("Solve DNS")
        token = challenge['token']
        key_authorization = self.compute_key_authorization(token)
        key_authorization_hash = hashlib.sha256(key_authorization).digest()
        value = base64.urlsafe_b64encode(key_authorization_hash).rstrip(b'=').decode()
        record = '_acme-challenge.' + identifier + '. 300 IN TXT "' + value + '"'
        self.dns_server.resolver.add_record(record)

    def check_authorizations(self):
        valid = False
        max_time = time.time() + self.timeout
        while not valid:
            valid = True
            for authorization in self.order['authorizations']:
                response = self.make_request(authorization, b'', {}).json()
                if response['status'] != 'valid':
                    valid = False
            time.sleep(self.retry_interval)
            if time.time() >= max_time:
                raise Exception("Timeout")
        print("Authorizations Valid")

    def check_order(self):
        max_time = time.time() + self.timeout
        response = self.make_request(self.order['url'], b'', {}).json()
        while response['status'] != 'ready':
            time.sleep(self.retry_interval)
            response = self.make_request(self.order['url'], b'', {}).json()
            if time.time() >= max_time:
                raise Exception("Timout")
        print("Order Ready")
  
    def finalize_order(self):
        print("Finalize Order")
        subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.order['identifiers'][0]['value'])])
        sites = []
        for identifier in self.order['identifiers']:
            sites.append(x509.DNSName(identifier['value']))
        extension = x509.SubjectAlternativeName(sites)
        csr = x509.CertificateSigningRequestBuilder()
        csr = csr.subject_name(subject_name)
        csr = csr.add_extension(extension, critical=False)
        csr = csr.sign(self.csr_key, hashes.SHA256())
        csr_bytes = csr.public_bytes(serialization.Encoding.DER)
        csr_encoded = base64.urlsafe_b64encode(csr_bytes).rstrip(b'=').decode()
        response = self.make_request(self.order['finalize'], {'csr': csr_encoded}, {}).json()
        response = self.make_request(self.order['url'], b'', {}).json()
        max_time = time.time() + self.timeout
        while response['status'] != 'valid':
            time.sleep(self.retry_interval)
            response = self.make_request(self.order['url'], b'', {}).json()
            if time.time() >= max_time:
                raise Exception("Timeout")
        self.order['certificate'] = response['certificate']

    def download_cert(self):
        print("Download Certificate")
        response = self.make_request(self.order['certificate'], b'', {'Accept': 'application/pem-certificate-chain'})
        self.certificate = response.content
        filepath = 'home/.crt'
        with open(filepath, 'wb') as f:
            f.write(self.certificate) 
        filepath = 'home/.key'
        key = self.csr_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        with open(filepath, 'wb') as f:
            f.write(key)
        
    def revoke_certificate(self):
        print("Revoke Certificate")
        DER_certificate = x509.load_pem_x509_certificate(self.certificate, default_backend()).public_bytes(serialization.Encoding.DER)
        DER_certificate_encoded = base64.urlsafe_b64encode(DER_certificate).rstrip(b'=').decode()
        response = self.make_request(self.dir['revokeCert'], {'certificate': DER_certificate_encoded}, {})

    def compute_key_authorization(self, token):
        thumbprint = self.compute_thumbprint()
        key_authorization = token + '.' + thumbprint
        return key_authorization.encode()

    def compute_thumbprint(self):
        jwk = json.dumps(self.key.jwk(), sort_keys=True, separators=(',', ':'))
        jwk_hash = hashlib.sha256(jwk.encode()).digest()
        thumbprint = base64.urlsafe_b64encode(jwk_hash).rstrip(b'=')
        return thumbprint.decode()
        
    

        

    def make_request(self, url, payload, headers):
        # a nonce can be stored and taken from a previous request. for more efficiency.
        # for now every request, requests a fresh nonce.
        nonce = self.session.head(url=self.dir['newNonce']).headers['Replay-Nonce']
        header = {'alg': 'ES256', 'nonce': nonce, 'url': url}
        jws = JWS(self.key)
        msg = jws.create(header, payload)
        headers.update({'Content-Type': 'application/jose+json'})
        response = self.session.post(url=url, headers=headers, data=msg, verify=False)
        return response