from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from .crypto_utils import (enc_pvt_key, save_file, setup_dirs, keygen, policy, load_encrypted_key, load_certificate, append_intermediate_policy, gen_leaf_key, save_unencrypted_key)
from .certificates import create_rootca_cert, parse_subject_dn
import logging
from .logger import log_event
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from .templates import build_template_extensions, build_ocsp_cert_extensions
from .csr import build_intermediate_csr, sign_intermediate_csr, signature_algorithm_for
from pathlib import Path
from .database import connect, insert_certificate
from .serial import generate_serial, to_hex
from .audit import AuditLog
from .policy import (check_rsa_size, check_ecc_size, check_validity, check_san, check_csr_signature_alg, check_pathlen, PolicyViolation)
from .transparency import append_ct
from .compromise import is_key_compromised, public_key_hash

logger = logging.getLogger("pki_audit")

def _cn_from_dn(dn: x509.Name) -> str:
    attrs = dn.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    return dn.rdns[0].rfc4514_string().split("=", 1)[1]

def _sans_from_csr(csr) -> list[str]:
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    out = []
    for d in san.get_values_for_type(x509.DNSName):
        out.append(f"dns:{d}")
    for ip in san.get_values_for_type(x509.IPAddress):
        out.append(f"ip:{ip}")
    for em in san.get_values_for_type(x509.RFC822Name):
        out.append(f"email:{em}")
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        out.append(f"uri:{uri}")
    return out

class RootCA:
    def __init__(self, out_dir: str, create_layout: bool = True, audit: AuditLog | None=None):
        self.out_dir = Path(out_dir).expanduser().resolve()
        if create_layout:
          self.pvt_dir, self.certs_dir, self.policy_path = setup_dirs(self.out_dir)
        else:
          self.pvt_dir = self.out_dir / "private"
          self.certs_dir = self.out_dir / "certs"
          self.policy_path = self.out_dir / "policy.txt"
        
        self.key_path = self.pvt_dir / "ca.key.pem"
        self.cert_path = self.certs_dir / "ca.cert.pem"
        self.audit = audit
        self.ct_path = self.out_dir / "audit" / "ct.log"
        logger.info(f"RootCA instance initialized for directory: {self.out_dir}")

    def initialize(self, subject: str, key_type: str, passphrase: bytes, key_size: int = 4096, validity_days: int = 3650) -> bool:
        role = "root"
        try:
            if key_type == "rsa":
                check_rsa_size(key_size, role)
            else:
                from cryptography.hazmat.primitives.asymmetric import ec as _ec
                size = {256: 256, 384: 384}.get(key_size, key_size)
                if size < 384:
                    raise PolicyViolation("Root CA ECC curve must be >= P-384")
            check_validity(validity_days, role)
        except PolicyViolation as e:
            if self.audit:
                self.audit.log("ca_init", status="failure",
                               message=str(e), level="AUDIT",
                               subject=subject, reason=str(e))
            raise

        if self.audit:
            self.audit.log("ca_init", status="in_progress",
                           message="Root CA init started", subject=subject)

        if self.key_path.exists() or self.cert_path.exists():
            log_event(logger, logging.WARNING, "CA initialization failed: files already exist", out_dir=str(self.out_dir))
            raise FileExistsError("CA already initialized. Remove existing files to reinitialize.")

        try:
            log_event(logger, logging.INFO, "Starting CA initialization process", 
                      key_type=key_type, key_size=key_size, subject=subject)
            pvt_key = keygen(key_type=key_type, key_size=key_size)
            log_event(logger, logging.INFO, "Private key generation is successfull")
            encd_key = enc_pvt_key(pvt_key, passphrase)
            log_event(logger, logging.INFO, "Private key encrypted and saved", 
                      key_path=str(self.key_path), permissions="0600")
            save_file(self.key_path, encd_key, file_mode=0o600)
            certificate = create_rootca_cert(private_key=pvt_key, subject_dn=subject, validity_days=validity_days)
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            save_file(self.cert_path, cert_pem, file_mode=0o644)
            log_event(logger, logging.INFO, "Root CA certificate generated and saved", 
                      cert_path=str(self.cert_path), serial_number=hex(certificate.serial_number))
            a=subject
            if "CN=" in subject:
                a = subject.split("CN=")[1].split(",")[0].split("/")[0]
            policy(policy_path=self.policy_path, ca_name=a, serial=hex(certificate.serial_number),
                   date_bf=certificate.not_valid_before_utc,
                   date_af=certificate.not_valid_after_utc,
                   key_type=key_type, key_size=pvt_key.key_size)
            log_event(logger, logging.INFO, "CA initialization is successfull", ca_name=a, validity_days=validity_days)

            if self.audit:
                self.audit.log("ca_init", status="success",
                              message="Root CA initialized",
                              serial=hex(certificate.serial_number),
                              subject=certificate.subject.rfc4514_string())
            return True
            
        except Exception as e:
            log_event(logger, logging.ERROR, "CA initialization failed", error_type=type(e).__name__, error_message=str(e))
            if self.key_path.exists():
                self.key_path.unlink()
            if self.cert_path.exists():
                self.cert_path.unlink()
            raise e

    def load_key(self, passphrase: bytes):
        if not self.key_path.exists():
            log_event(logger, logging.ERROR, "Failed to load key: file not found", key_path=str(self.key_path))
            raise FileNotFoundError("CA private key not found")

        try:
            with open(self.key_path, "rb") as f:
                key_data = f.read()
            key = serialization.load_pem_private_key(key_data, password=passphrase, backend=default_backend())
            log_event(logger, logging.INFO, "Private key loading is successfull")
            return key

        except Exception as e:
            log_event(logger, logging.ERROR, "Failed to decrypt orr load private key", error_message=str(e))
            raise e


    def issue_intermediate(self, *, root_cert_path: str, root_key_path: str, root_passphrase: bytes, subject: str, key_type: str,
                           key_size: int, passphrase: bytes, validity_days: int, pathlen: int, db_path: str |Path = "./pki/micropki.db") -> x509.Certificate:
        try:
            if key_type == "rsa":
                check_rsa_size(key_size, "intermediate")
            else:
                if key_size < 384:
                    raise PolicyViolation("Intermediate ECC must be >= P-384")
            check_validity(validity_days, "intermediate")
            check_pathlen(pathlen, "intermediate")
        except PolicyViolation as e:
            if self.audit:
                self.audit.log("issue_intermediate", status="failure",
                               message=str(e), level="AUDIT",
                               subject=subject, reason=str(e))
            raise

        if self.audit:
            self.audit.log("issue_intermediate", status="in_progress",
                           message="Issuing intermediate CA", subject=subject)  

        root_cert = load_certificate(Path(root_cert_path))
        root_key = load_encrypted_key(Path(root_key_path), root_passphrase)

        intermediate_key = keygen(key_type=key_type, key_size=key_size)
        csr = build_intermediate_csr(subject, intermediate_key, pathlen)
        key_path = self.pvt_dir / "intermediate.key.pem"
        cert_path = self.certs_dir / "intermediate.cert.pem"

        conn = connect(db_path)
        try:
            serial_int = generate_serial(conn)
            cert = sign_intermediate_csr(csr, root_cert, root_key,
                                         validity_days, pathlen,
                                         serial_number=serial_int)
            insert_certificate(
                conn,
                serial_hex=to_hex(serial_int),
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                not_before=cert.not_valid_before_utc.isoformat(),
                not_after=cert.not_valid_after_utc.isoformat(),
                cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            )
            try:
                enc_key = enc_pvt_key(intermediate_key, passphrase)
                self.pvt_dir.mkdir(parents=True, exist_ok=True)
                self.certs_dir.mkdir(parents=True, exist_ok=True)
                save_file(key_path, enc_key, file_mode=0o600)
                save_file(cert_path, cert.public_bytes(serialization.Encoding.PEM),
                          file_mode=0o644)
            except Exception:
                conn.execute("DELETE FROM certificates WHERE serial_hex = ?",
                             (to_hex(serial_int),))
                conn.commit()
                raise
        finally:
            conn.close()

        append_intermediate_policy(
            self.policy_path,
            subject=cert.subject.rfc4514_string(),
            serial=hex(cert.serial_number),
            date_bf=cert.not_valid_before_utc,
            date_af=cert.not_valid_after_utc,
            key_type=key_type, key_size=intermediate_key.key_size,
            pathlen=pathlen, issuer=root_cert.subject.rfc4514_string(),
        )
        log_event(logger, logging.INFO, "Intermediate CA issued",
                  cert_path=str(cert_path), key_path=str(key_path),
                  db_path=str(db_path))

        if self.audit:
            self.audit.log("issue_intermediate", status="success",
                           message="Intermediate CA issued",
                           serial=hex(cert.serial_number),
                           subject=cert.subject.rfc4514_string(),
                           pathlen=pathlen)
        append_ct(self.ct_path, cert)
        return cert

    def issue_cert(self, *, ca_cert_path: str, ca_key_path: str, ca_passphrase: bytes, template: str, subject: str, sans: list[str],out_dir: str,
                   validity_days: int, key_type: str = "rsa", csr_path: str | None = None, db_path: str | Path = "./pki/micropki.db") -> x509.Certificate:
        try:
            check_validity(validity_days, "leaf")

            if csr_path:
                raw = Path(csr_path).read_bytes()
                csr = x509.load_pem_x509_csr(raw, default_backend())
                if not csr.is_signature_valid:
                    raise ValueError("CSR signature is invalid")
                check_csr_signature_alg(csr)
                if is_key_compromised(db_path, csr):
                    raise PolicyViolation("Public key is marked compromised")
                leaf_key = None
                leaf_pub = csr.public_key()
                if isinstance(leaf_pub, rsa.RSAPublicKey):
                    check_rsa_size(leaf_pub.key_size, "leaf")
                elif isinstance(leaf_pub,_ec.EllipticCurvePublicKey):
                    check_ecc_size(leaf_pub.curve, "leaf")
                subject_dn = csr.subject
                sans = _sans_from_csr(csr)
                try:
                    san_ext = csr.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName).value
                    check_san(san_ext, template)
                except x509.ExtensionNotFound:
                    pass
            else:
                leaf_key = gen_leaf_key(key_type)
                leaf_pub = leaf_key.public_key()
                if key_type == "rsa":
                    check_rsa_size(leaf_pub.key_size, "leaf")
                else:
                    check_ecc_size(leaf_pub.curve, "leaf")
                subject_dn = parse_subject_dn(subject)
                from .san import parse_san
                san_ext = parse_san(sans, template)
                if san_ext is not None:
                    check_san(san_ext, template)
        except (PolicyViolation, ValueError) as e:
            if self.audit:
                self.audit.log("issue_certificate", status="failure",
                               message=str(e), level="AUDIT",
                               template=template, subject=subject,
                               reason=str(e))
            raise

        if self.audit:
            self.audit.log("issue_certificate", status="in_progress",
                           message="Issuing leaf certificate",
                           template=template, subject=subject)

        ca_cert = load_certificate(Path(ca_cert_path))
        ca_key = load_encrypted_key(Path(ca_key_path), ca_passphrase)

        if csr_path:
            raw = Path(csr_path).read_bytes()
            csr = x509.load_pem_x509_csr(raw, default_backend())
            if not csr.is_signature_valid:
                raise ValueError("CSR signature is invalid")
            leaf_key = None
            leaf_pub = csr.public_key()
            subject_dn = csr.subject
            sans = _sans_from_csr(csr)
            log_event(logger, logging.INFO, "Signing external CSR",
                      csr_path=csr_path, subject=subject_dn.rfc4514_string())
        else:
            leaf_key = gen_leaf_key(key_type)
            leaf_pub = leaf_key.public_key()
            subject_dn = parse_subject_dn(subject)
            log_event(logger, logging.INFO, "Generated leaf key",
                      key_type=key_type)

        out = Path(out_dir).expanduser()
        out.mkdir(parents=True, exist_ok=True)
        cn = _cn_from_dn(subject_dn)
        cert_path = out / f"{cn}.cert.pem"
        key_path = out / f"{cn}.key.pem"

        conn = connect(db_path)
        try:
            serial_int = generate_serial(conn)
            now = datetime.now(timezone.utc)
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject_dn)
                .issuer_name(ca_cert.subject)
                .public_key(leaf_pub)
                .serial_number(serial_int)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=validity_days))
            )
            for ext, critical in build_template_extensions(template, leaf_pub, sans):
                builder = builder.add_extension(ext, critical=critical)
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_pub), critical=False)
            try:
                ca_ski = ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                    critical=False)
            except x509.ExtensionNotFound:
                log_event(logger, logging.WARNING,
                          "Intermediate CA certificate has no SKI; AKI skipped",
                          ca_cert=str(ca_cert_path))

            cert = builder.sign(private_key=ca_key,
                                algorithm=signature_algorithm_for(ca_key),
                                backend=default_backend())

            insert_certificate(
                conn,
                serial_hex=to_hex(serial_int),
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                not_before=cert.not_valid_before_utc.isoformat(),
                not_after=cert.not_valid_after_utc.isoformat(),
                cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            )
            try:
                save_file(cert_path, cert.public_bytes(serialization.Encoding.PEM),
                          file_mode=0o644)
                if leaf_key is not None:
                    save_unencrypted_key(key_path, leaf_key)
            except Exception:
                conn.execute("DELETE FROM certificates WHERE serial_hex = ?",
                             (to_hex(serial_int),))
                conn.commit()
                raise
        finally:
            conn.close()

        log_event(logger, logging.INFO, "Leaf certificate issued",
                  template=template, subject=subject_dn.rfc4514_string(),
                  sans=sans, serial=hex(cert.serial_number),
                  cert_path=str(cert_path), db_path=str(db_path))

        if self.audit:
            self.audit.log("issue_certificate", status="success",
                           message="Leaf certificate issued",
                           template=template,
                           serial=hex(cert.serial_number),
                           subject=cert.subject.rfc4514_string(),
                           sans=sans)
        append_ct(self.ct_path, cert)
        return cert

    def issue_ocsp_cert(self, *, ca_cert_path: str, ca_key_path: str,
                        ca_passphrase: bytes, subject: str,
                        key_type: str, key_size: int,
                        sans: list[str], out_dir: str,
                        validity_days: int = 365,
                        db_path: str | Path = "./pki/micropki.db") -> x509.Certificate:
        try:
            ca_cert = load_certificate(Path(ca_cert_path))
            ca_key = load_encrypted_key(Path(ca_key_path), ca_passphrase)

            if key_type == "rsa" and key_size < 2048:
               raise ValueError("OCSP responder key: RSA must be >= 2048")
            if key_type == "ecc" and key_size not in (256, 384):
                raise ValueError("OCSP responder key: ECC must be P-256 or P-384")

            leaf_key = gen_leaf_key(key_type)
            leaf_pub = leaf_key.public_key()
            subject_dn = parse_subject_dn(subject)

            out = Path(out_dir).expanduser()
            out.mkdir(parents=True, exist_ok=True)
            cn = _cn_from_dn(subject_dn)
            cert_path = out / f"{cn}.cert.pem"
            key_path = out / f"{cn}.key.pem"

        except (PolicyViolation, ValueError) as e:
            if self.audit:
                self.audit.log("issue_ocsp_certificate", status="failure",
                               message=str(e), level="AUDIT",
                               subject=subject,
                               reason=str(e))
            raise

        conn = connect(db_path)
        try:
            serial_int = generate_serial(conn)
            now = datetime.now(timezone.utc)
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject_dn)
                .issuer_name(ca_cert.subject)
                .public_key(leaf_pub)
                .serial_number(serial_int)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=validity_days))
            )
            for ext, critical in build_ocsp_cert_extensions(leaf_pub, sans):
                builder = builder.add_extension(ext, critical=critical)
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_pub), critical=False)
            try:
                ca_ski = ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value
                builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                    critical=False)
            except x509.ExtensionNotFound:
                pass

            cert = builder.sign(private_key=ca_key,
                                algorithm=signature_algorithm_for(ca_key),
                                backend=default_backend())

            insert_certificate(
                conn,
                serial_hex=to_hex(serial_int),
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                not_before=cert.not_valid_before_utc.isoformat(),
                not_after=cert.not_valid_after_utc.isoformat(),
                cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            )
            try:
                save_file(cert_path, cert.public_bytes(serialization.Encoding.PEM),
                          file_mode=0o644)
                save_unencrypted_key(key_path, leaf_key)
            except Exception:
                conn.execute("DELETE FROM certificates WHERE serial_hex = ?",
                             (to_hex(serial_int),))
                conn.commit()
                raise
        finally:
            conn.close()

        log_event(logger, logging.INFO, "OCSP responder certificate issued",
                  subject=subject_dn.rfc4514_string(),
                  serial=hex(cert.serial_number),
                  cert_path=str(cert_path), key_path=str(key_path))

        if self.audit:
            self.audit.log("issue_ocsp_certificate", status="success",
                           message="OCSP responder certificate issued",
                           serial=hex(cert.serial_number),
                           subject=cert.subject.rfc4514_string(),
                           sans=sans)
        append_ct(self.ct_path, cert)
        return cert

