from OpenSSL import crypto
import os

def create_self_signed_cert(cert_dir):
    if not os.path.exists((cert_dir)):
        os.makedirs(cert_dir)

    cert_file = os.path.join(cert_dir, "selfsigned.crt")
    key_file = os.path.join(cert_dir, "private.key")

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Florida"
    cert.get_subject().L = "Miami"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
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

#create_self_signed_cert("C:\\Users\\migue\\PycharmProjects\\final_project\\secureAuthentication")
create_self_signed_cert("./")
