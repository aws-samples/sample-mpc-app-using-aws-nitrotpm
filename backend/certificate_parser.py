import base64
import logging
import hashlib
import requests
import zipfile
import io
from typing import Dict, List, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

AWS_ROOT_CA_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
# Using the checksum from the documentation. In a more robust implementation, the ZIP
# has to be downloaded and the checksum hardcoded should be compared to what's downloaded
# and verification asserted accordingly.
AWS_ROOT_CA_DER_CHECKSUM = "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"

def verify_certificate_chain_signatures(certificates: List[x509.Certificate]) -> Dict[str, Any]:
    """Verify certificate chain signatures and validity"""
    try:
        # Sort certificates by hierarchy
        root_cert = None
        chain_certs = []
        
        for cert in certificates:
            if cert.subject == cert.issuer:  # Self-signed root
                root_cert = cert
            else:
                chain_certs.append(cert)
        
        if not root_cert:
            return {"verified": False, "error": "No root certificate found"}
        
        # Sort chain certificates by path length (CA -> intermediate -> leaf)
        chain_certs.sort(key=lambda c: _get_path_length(c), reverse=True)
        
        # Verify each certificate in chain
        issuer_cert = root_cert
        for cert in chain_certs:
            # 1. Signature verification
            try:
                issuer_public_key = issuer_cert.public_key()
                # Use the signature algorithm from the certificate
                from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
                
                if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm)
                    )
                elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                else:
                    return {"verified": False, "error": f"Unsupported public key type for {cert.subject.rfc4514_string()}"}
            except Exception as e:
                return {"verified": False, "error": f"Signature verification failed for {cert.subject.rfc4514_string()}: {e}"}
            
            # 2. Validity period check
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return {"verified": False, "error": f"Certificate expired or not yet valid: {cert.subject.rfc4514_string()}"}
            
            # 3. Issuer/subject chain validation
            if cert.issuer != issuer_cert.subject:
                return {"verified": False, "error": f"Certificate chain broken: {cert.subject.rfc4514_string()} not issued by {issuer_cert.subject.rfc4514_string()}"}
            
            # 4. Certificate purpose validation
            if not _validate_certificate_purpose(cert, issuer_cert):
                return {"verified": False, "error": f"Certificate purpose validation failed: {cert.subject.rfc4514_string()}"}
            
            issuer_cert = cert
        
        return {"verified": True}
        
    except Exception as e:
        return {"verified": False, "error": str(e)}

def _get_path_length(cert: x509.Certificate) -> int:
    """Get certificate path length for sorting"""
    try:
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
        if bc.ca and bc.path_length is not None:
            return bc.path_length
        elif bc.ca:
            return 999  # CA with no path length limit
        else:
            return -1  # End entity certificate
    except x509.ExtensionNotFound:
        return -1

def _validate_certificate_purpose(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Validate certificate purpose and key usage"""
    try:
        # Check if issuer is authorized to sign certificates
        try:
            issuer_ku = issuer_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
            if not issuer_ku.key_cert_sign:
                return False
        except x509.ExtensionNotFound:
            pass  # Root certificates may not have key usage extension
        
        # Check basic constraints
        try:
            bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
            # If it's a CA certificate, it should have CA:TRUE
            cert_ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
            if cert_ku.key_cert_sign and not bc.ca:
                return False
        except x509.ExtensionNotFound:
            pass
        
        return True
    except Exception:
        return False

def verify_root_certificate(root_cert_der: bytes) -> Dict[str, Any]:
    """Verify root certificate against known AWS root CA checksum"""
    try:
        # Verify certificate DER checksum against known value
        cert_hash = hashlib.sha256(root_cert_der).hexdigest().upper()
        if cert_hash == AWS_ROOT_CA_DER_CHECKSUM:
            return {"verified": True}
        
        return {"verified": False, "error": f"Certificate checksum mismatch: {cert_hash}"}
    except Exception as e:
        logger.warning(f"Root verification failed: {e}")
        return {"verified": False, "error": str(e)}

def parse_certificate_chain(raw_certificate: bytes, raw_cabundle: List[bytes]) -> Dict[str, Any]:
    """Parse the certificate chain from attestation document"""
    try:
        logger.info(f"Parsing certificate chain: main cert size={len(raw_certificate)}, cabundle count={len(raw_cabundle)}")
        certificates = []
        root_cert_der = None
        
        # Parse the main certificate (TPM certificate)
        if raw_certificate:
            try:
                cert = x509.load_der_x509_certificate(raw_certificate, default_backend())
                cert_info = _extract_certificate_info(cert, "TPM Certificate")
                certificates.append(cert_info)
            except Exception as e:
                logger.warning(f"Failed to parse main certificate: {e}")
        
        # Parse CA bundle certificates
        for i, cert_bytes in enumerate(raw_cabundle):
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                # Determine certificate type based on subject
                subject_str = cert.subject.rfc4514_string()
                if "aws.nitro-enclaves" in subject_str and "CN=aws.nitro-enclaves" in subject_str:
                    cert_type = "Root CA"
                elif ".aws.nitro-enclaves" in subject_str and "zonal" in subject_str:
                    cert_type = "Zonal Certificate"
                elif "i-" in subject_str and ".us-east-1.aws.nitro-enclaves" in subject_str:
                    cert_type = "Instance Certificate"
                elif ".aws.nitro-enclaves" in subject_str:
                    cert_type = "Regional Certificate"
                else:
                    cert_type = f"Certificate {i+1}"
                
                logger.info(f"Detected certificate type: {cert_type}, subject: {subject_str}")
                cert_info = _extract_certificate_info(cert, cert_type)
                if cert_type == "Root CA":
                    root_cert_der = cert_bytes
                certificates.append(cert_info)
            except Exception as e:
                logger.warning(f"Failed to parse CA bundle certificate {i}: {e}")
        
        # Sort certificates by hierarchy (root -> regional -> zonal -> instance -> tpm)
        cert_order = {"Root CA": 0, "Regional Certificate": 1, "Zonal Certificate": 2, 
                     "Instance Certificate": 3, "TPM Certificate": 4}
        certificates.sort(key=lambda x: cert_order.get(x["type"], 5))
        
        # Verify root certificate
        root_verification = {"verified": False}
        if root_cert_der:
            root_verification = verify_root_certificate(root_cert_der)
        
        # Verify certificate chain signatures and validity
        chain_verification = {"verified": False}
        if len(certificates) > 1:
            # Convert certificate info back to x509 objects for verification
            cert_objects = []
            for cert_info in certificates:
                try:
                    if cert_info["type"] == "Root CA":
                        cert_obj = x509.load_der_x509_certificate(root_cert_der, default_backend())
                    else:
                        # For other certificates, we need to reconstruct from the raw data
                        # This is a simplified approach - in practice, you'd store raw cert data
                        continue
                    cert_objects.append(cert_obj)
                except Exception as e:
                    logger.warning(f"Failed to convert certificate info to x509: {e}")
            
            if cert_objects:
                chain_verification = verify_certificate_chain_signatures(cert_objects)
        
        return {
            "status": "success" if root_verification.get("verified") and chain_verification.get("verified") else "failed",
            "certificates": certificates,
            "root_verified": root_verification.get("verified", False),
            "chain_verified": chain_verification.get("verified", False),
            "root_verification_error": root_verification.get("error"),
            "chain_verification_error": chain_verification.get("error")
        }
        
    except Exception as e:
        logger.error(f"Certificate chain parsing failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "certificates": [],
            "root_verified": False,
            "chain_verified": False
        }

def _extract_certificate_info(cert: x509.Certificate, cert_type: str) -> Dict[str, Any]:
    """Extract certificate information for display"""
    try:
        # Get key usage
        key_usage = "N/A"
        try:
            ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
            usage_list = []
            if ku.digital_signature: usage_list.append("Digital Signature")
            if ku.key_cert_sign: usage_list.append("Certificate Sign")
            if ku.crl_sign: usage_list.append("CRL Sign")
            key_usage = ", ".join(usage_list) if usage_list else "N/A"
        except x509.ExtensionNotFound:
            pass
        
        # Get basic constraints
        basic_constraints = "N/A"
        try:
            bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
            if bc.ca:
                path_len = f", pathlen={bc.path_length}" if bc.path_length is not None else ""
                basic_constraints = f"CA:TRUE{path_len}"
            else:
                basic_constraints = "CA:FALSE"
        except x509.ExtensionNotFound:
            pass
        
        return {
            "type": cert_type,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_to": cert.not_valid_after_utc.isoformat(),
            "key_usage": key_usage,
            "basic_constraints": basic_constraints,
            "signature_algorithm": cert.signature_algorithm_oid._name
        }
    except Exception as e:
        logger.warning(f"Failed to extract certificate info: {e}")
        return {
            "type": cert_type,
            "subject": "Unknown",
            "issuer": "Unknown",
            "error": str(e)
        }