from OpenSSL import crypto, SSL
import os

CERT_FILE = "nginx-selfsigned.crt"
KEY_FILE = "nginx-selfsigned.key"

def create_self_signed_cert(cert_dir):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Department"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    with open(os.path.join(cert_dir, CERT_FILE), "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(os.path.join(cert_dir, KEY_FILE), "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == "__main__":
    create_self_signed_cert("/etc/nginx/certs")