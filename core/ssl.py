import ssl
import socket
import asyncio
import datetime
from typing import Dict
from cryptography import x509

class SSLAnalyzer:
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    async def analyze(self) -> Dict:
        loop = asyncio.get_event_loop()
        def _fetch():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True))
        try:
            cert = await loop.run_in_executor(None, _fetch)
            now = datetime.datetime.now(datetime.timezone.utc)
            expiry = cert.not_valid_after_utc
            days_left = (expiry - now).days
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except: sans = []
            return {"subject": str(cert.subject), "issuer": str(cert.issuer), "serial_number": str(cert.serial_number), "not_before": str(cert.not_valid_before_utc), "not_after": str(expiry), "days_remaining": days_left, "expired": days_left < 0, "expiring_soon": 0 <= days_left <= 30, "subject_alt_names": sans, "signature_algorithm": cert.signature_algorithm_oid._name, "version": cert.version.value}
        except Exception as e:
            return {"error": str(e)}
