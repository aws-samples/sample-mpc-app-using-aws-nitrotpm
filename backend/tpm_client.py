import os
from typing import Dict, Any
import cbor2
import base64
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TPMClient:
    def __init__(self, device_path: str = "/dev/tpm0"):
        self.device_path = device_path
        logger.debug(f"TPM client initialized with device: {device_path}")
    
    def is_available(self) -> bool:
        return os.path.exists(self.device_path)
    
    def get_attestation_document(self, user_data: bytes = None, nonce: bytes = None, public_key: bytes = None) -> bytes:
        logger.debug("Using Rust tool to get attestation document")
        
        import subprocess  # nosec B404
        import tempfile
        
        try:
            # Create temp files for arguments
            temp_key_file = None
            if public_key:
                temp_key_file = tempfile.NamedTemporaryFile(delete=False)
                temp_key_file.write(public_key)
                temp_key_file.flush()
                temp_key_file.close()
            
            temp_user_file = None
            if user_data:
                temp_user_file = tempfile.NamedTemporaryFile(delete=False)
                temp_user_file.write(user_data)
                temp_user_file.flush()
                temp_user_file.close()
            
            temp_nonce_file = None
            if nonce:
                temp_nonce_file = tempfile.NamedTemporaryFile(delete=False)
                temp_nonce_file.write(nonce)
                temp_nonce_file.flush()
                temp_nonce_file.close()
            
            # Build command arguments
            cmd_args = ['nitro-tpm-attest']
            if public_key and temp_key_file:
                cmd_args.append('--public-key')
                cmd_args.append(temp_key_file.name)
            if user_data and temp_user_file:
                cmd_args.append('--user-data')
                cmd_args.append(temp_user_file.name)
            if nonce and temp_nonce_file:
                cmd_args.append('--nonce')
                cmd_args.append(temp_nonce_file.name)
            
            # nosemgrep: dangerous-subprocess-use-audit
            result = subprocess.run(cmd_args, capture_output=True, timeout=30)  # nosec B603 B607
            
            # Cleanup temp files
            import os
            for temp_file in [temp_key_file, temp_user_file, temp_nonce_file]:
                if temp_file:
                    os.unlink(temp_file.name)
            
            if result.returncode != 0:
                raise Exception(f"Rust tool failed: {result.stderr.decode()}")
            
            raw_output = result.stdout
            logger.debug(f"Rust tool output: {len(raw_output)} bytes")
            
            # The output is raw CBOR attestation document
            return raw_output
                
        except subprocess.TimeoutExpired:
            raise Exception("Rust tool timed out")
        except Exception as e:
            logger.warning(f"Failed to call Rust tool: {e}")
            raise

def parse_attestation_document(doc_bytes: bytes) -> Dict[str, Any]:
    logger.debug(f"Parsing attestation document: {len(doc_bytes)} bytes")
    
    try:
        # Parse the CBOR data from Rust tool
        parsed = cbor2.loads(doc_bytes)
        
        # If it's a list (from Rust tool), the attestation document is in item 2
        if isinstance(parsed, list) and len(parsed) > 2:
            doc = cbor2.loads(parsed[2])  # Item 2 contains the actual attestation document
        elif isinstance(parsed, dict):
            doc = parsed
        else:
            raise Exception(f"Unexpected CBOR structure: {type(parsed)}")
        
        logger.debug(f"Document keys: {list(doc.keys())}")
        
        # Parse PCRs from nitrotpm_pcrs
        pcrs = {}
        if "nitrotpm_pcrs" in doc:
            for pcr_num, pcr_value in doc["nitrotpm_pcrs"].items():
                if isinstance(pcr_value, str):
                    # Convert base64 to hex
                    try:
                        pcr_bytes = base64.b64decode(pcr_value)
                        pcrs[str(pcr_num)] = pcr_bytes.hex()
                    except:
                        pcrs[str(pcr_num)] = pcr_value
                else:
                    pcrs[str(pcr_num)] = pcr_value.hex()
        
        return {
            "module_id": doc.get("module_id", "Unknown"),
            "timestamp": doc.get("timestamp", 0),
            "digest": doc.get("digest", "SHA384"),
            "pcrs": pcrs,
            "certificate": base64.b64encode(doc.get("certificate", b"")).decode() if doc.get("certificate") else "",
            "cabundle": [base64.b64encode(cert).decode() for cert in doc.get("cabundle", [])],
            "public_key": base64.b64encode(doc.get("public_key", b"")).decode() if doc.get("public_key") else "",
            "user_data": base64.b64encode(doc.get("user_data", b"")).decode() if doc.get("user_data") else None,
            "nonce": base64.b64encode(doc.get("nonce", b"")).decode() if doc.get("nonce") else None,
            "raw_certificate": doc.get("certificate", b""),
            "raw_cabundle": doc.get("cabundle", [])
        }
    except Exception as e:
        logger.warning(f"Failed to parse attestation document: {e}")
        raise Exception(f"Invalid attestation document format: {e}")