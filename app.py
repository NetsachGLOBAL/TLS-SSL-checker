from flask import Flask, render_template, request
import ssl
import socket
from datetime import datetime

app = Flask(__name__)

def check_tls_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()

                # Certificate details
                cert_subject = dict(x[0] for x in cert['subject'])
                cert_issuer = dict(x[0] for x in cert['issuer'])
                cert_valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                cert_valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                return {
                    "hostname": hostname,
                    "cert_subject": cert_subject,
                    "cert_issuer": cert_issuer,
                    "cert_valid_from": cert_valid_from,
                    "cert_valid_until": cert_valid_until,
                    "cipher_suite": cipher,
                    "protocol_version": protocol_version,
                }
    except Exception as e:
        return {"error": str(e)}

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        hostname = request.form.get("hostname")
        result = check_tls_ssl(hostname)
    return render_template("index_result.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
