from OpenSSL import crypto
import os


def create_self_signed_cert(cert_dir):
    if not os.path.exists((cert_dir)):
        os.makedirs(cert_dir)

    # Create files for the certificate and keys
    cert_file = os.path.join(cert_dir, "selfsigned.crt")
    key_file = os.path.join(cert_dir, "private.key")

    # Create public/private key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Use standard format for certificates on TLS/SSL connections
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Florida"
    cert.get_subject().L = "Miami"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)   # Certificate valid for one year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')


    open(cert_file, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    )
    open(key_file, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")
    )

    print("Certificates created")

# Create a new certificate and key file and store it in local directory
create_self_signed_cert("./")
