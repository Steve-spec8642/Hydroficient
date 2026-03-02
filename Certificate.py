import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ca_certificate():
    """Generate the Certificate Authority (CA) certificate"""

    print("      Generating CA private key (2048 bits)...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grand Marina Hotel"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Water Systems Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Grand Marina Root CA"),
    ])

    print("      Creating CA certificate (valid for 10 years)...")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)  # Self-signed: issuer = subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    print("      CA certificate created successfully!")
    return ca_key, ca_cert


def generate_server_certificate(ca_key, ca_cert):
    """Generate the server certificate signed by the CA"""

    print("      Generating server private key (2048 bits)...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    server_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grand Marina Hotel"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MQTT Broker"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    print("      Creating server certificate (valid for 1 year)...")
    print("      Common Name: localhost")
    print("      Subject Alternative Names: localhost, 127.0.0.1")

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)  # CA is the issuer
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())  # Signed by CA's key
    )

    print("      Server certificate created successfully!")
    return server_key, server_cert


def save_certificates(ca_cert, server_cert, server_key, output_dir="certs"):
    """Save all certificates and keys to files"""

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # Save CA certificate (public)
    ca_path = output_path / "ca.pem"
    with open(ca_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"      Saved: {ca_path}")

    # Save server certificate (public)
    server_cert_path = output_path / "server.pem"
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    print(f"      Saved: {server_cert_path}")

    # Save server private key (SECRET!)
    server_key_path = output_path / "server-key.pem"
    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"      Saved: {server_key_path}")


def verify_certificates(ca_cert, server_cert):
    """Verify the certificate chain looks correct"""
    print("\n      Verifying certificates...")
    print(f"      CA Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"      CA Valid Until: {ca_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    print(f"      Server Subject: {server_cert.subject.rfc4514_string()}")
    print(f"      Server Issuer: {server_cert.issuer.rfc4514_string()}")
    print(f"      Server Valid Until: {server_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")

    if server_cert.issuer == ca_cert.subject:
        print("      Chain verified: Server cert is signed by CA")
    else:
        print("      WARNING: Certificate chain could not be verified!")


# --- Main ---
print("=======================================================")
print("  Certificate Generation for Grand Marina Hotel")
print("=======================================================\n")

print("[1/3] Generating Certificate Authority (CA)...")
ca_key, ca_cert = generate_ca_certificate()

print("\n[2/3] Generating Server Certificate...")
server_key, server_cert = generate_server_certificate(ca_key, ca_cert)

print("\n[3/3] Saving certificates to certs/ folder...")
save_certificates(ca_cert, server_cert, server_key)

verify_certificates(ca_cert, server_cert)

print("\n=======================================================")
print("  Certificates generated successfully!")
print("=======================================================")
print("\nFiles created:")
print("  certs/ca.pem         - CA certificate (share with clients)")
print("  certs/server.pem     - Server certificate (for Mosquitto)")
print("  certs/server-key.pem - Server private key (keep secret!)")