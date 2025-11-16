import os
import boto3
import hashlib
import struct
import subprocess  # nosec B404
import logging
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
import requests
import json

logger = logging.getLogger(__name__)

class ModelManager:
    def __init__(self):
        # Get region from IMDS
        import urllib3
        http = urllib3.PoolManager()
        token_response = http.request('PUT', 'http://169.254.169.254/latest/api/token', 
                                     headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})
        token = token_response.data.decode('utf-8')
        region_response = http.request('GET', 'http://169.254.169.254/latest/meta-data/placement/region',
                                      headers={'X-aws-ec2-metadata-token': token})
        region = region_response.data.decode('utf-8')
        
        # Configure S3 client with optimized settings for large file downloads
        from boto3.s3.transfer import TransferConfig
        
        config = boto3.session.Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=50
        )
        self.s3_client = boto3.client('s3', region_name=region, config=config)
        
        # Optimized transfer config for large files
        self.transfer_config = TransferConfig(
            multipart_threshold=1024 * 1024 * 100,  # 100MB threshold
            max_concurrency=10,
            multipart_chunksize=1024 * 1024 * 100,  # 100MB chunks
            use_threads=True
        )
        
        self.kms_client = boto3.client('kms', region_name=region)
        self.models_dir = "/mnt/instance-store/models"
        self.ollama_url = "http://localhost:11434"
        
        # Ensure models directory exists
        os.makedirs(self.models_dir, exist_ok=True)
    
    def download_encrypted_model(self, bucket: str, model_key: str, progress_callback=None) -> Dict[str, Any]:
        """Download encrypted model from S3"""
        try:
            logger.info(f"Downloading encrypted model from s3://{bucket}/{model_key}")
            
            # Use temporary file for multipart download
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.flush()
            temp_file.close()
            temp_path = temp_file.name
            
            # Get file size first for progress calculation
            head_response = self.s3_client.head_object(Bucket=bucket, Key=model_key)
            total_size = head_response['ContentLength']
            logger.info(f"Model file size: {total_size} bytes")
            
            # Track cumulative progress for S3 transfer
            cumulative_bytes = 0
            
            def s3_progress_callback(bytes_transferred):
                nonlocal cumulative_bytes
                cumulative_bytes += bytes_transferred
                if progress_callback and total_size > 0:
                    progress = (cumulative_bytes / total_size) * 100
                    logger.info(f"S3 download progress: {progress:.1f}% ({cumulative_bytes}/{total_size})")
                    progress_callback('download_model', progress, cumulative_bytes, total_size)
            
            # Download using optimized transfer manager
            self.s3_client.download_file(
                bucket, model_key, temp_path,
                Config=self.transfer_config,
                Callback=s3_progress_callback
            )
            
            logger.info(f"Downloaded encrypted model to {temp_path}")
            
            return {
                "status": "success",
                "encrypted_path": temp_path
            }
            
        except Exception as e:
            logger.warning(f"Failed to download encrypted model: {e}")
            return {"status": "error", "message": str(e)}
    
    def decrypt_model(self, encrypted_path: str, bucket: str, datakey_key: str, kms_key_id: str, attestation_doc: bytes) -> Dict[str, Any]:
        """Decrypt model using KMS with proper attestation flow"""
        try:
            import base64
            import tempfile
            import subprocess  # nosec B404
            
            # Step 1: Generate RSA key pair
            logger.info("Generating RSA key pair for attestation")
            
            try:
                # Generate private key
                private_key_result = subprocess.run(['openssl', 'genrsa'], capture_output=True, text=True, check=True)  # nosec B603 B607
                private_key_pem = private_key_result.stdout
                logger.info("Private key generated successfully")
                
                # Generate public key in DER format and base64 encode (like CLI example)
                public_key_result = subprocess.run(['openssl', 'rsa', '-pubout', '-outform', 'DER'], input=private_key_pem.encode(), capture_output=True, check=True)  # nosec B603 B607
                public_key_der = public_key_result.stdout
                # Base64 encode the DER public key (matching CLI example)
                public_key_b64 = base64.b64encode(public_key_der).decode()
                logger.info("Public key generated and base64 encoded successfully")
                
            except Exception as key_error:
                logger.warning(f"Key generation failed: {key_error}")
                raise
            
            # Step 2: Get attestation document with public key
            logger.info("Getting attestation document with public key")
            with tempfile.NamedTemporaryFile() as pub_key_file:
                # Write the DER-encoded public key to the temporary file
                pub_key_file.write(base64.b64decode(public_key_b64))
                pub_key_file.flush()
                
                # Use the exact same command as test.sh that works
                attest_result = subprocess.run(['nitro-tpm-attest', '--public-key', pub_key_file.name], capture_output=True, timeout=30)  # nosec B603 B607
                
                if attest_result.returncode != 0:
                    logger.error(f"Attestation stderr: {attest_result.stderr.decode()}")
                    raise Exception(f"Attestation failed: {attest_result.stderr.decode()}")
                
                attestation_doc_with_key = attest_result.stdout
                logger.info(f"Raw attestation document size: {len(attestation_doc_with_key)} bytes")
                
                # Base64 encode the binary data directly (avoiding shell variable corruption)
                attestation_b64_raw = base64.b64encode(attestation_doc_with_key).decode()
                logger.info(f"Attestation b64 type: {type(attestation_b64_raw)}, length: {len(attestation_b64_raw)}")
                logger.info(f"Binary attestation doc first 50 bytes (hex): {attestation_doc_with_key[:50].hex()}")
            
            # Step 3: Download encrypted datakey
            logger.info(f"Downloading encrypted datakey from s3://{bucket}/{datakey_key}")
            datakey_response = self.s3_client.get_object(Bucket=bucket, Key=datakey_key)
            encrypted_datakey = datakey_response['Body'].read()
            
            # Step 4: KMS decrypt with attestation document
            logger.info("Decrypting datakey with KMS and attestation document")
            logger.info(f"Attestation document size: {len(attestation_doc_with_key)} bytes")
            logger.info(f"Attestation document (first 100 chars): {attestation_b64_raw[:100]}...")
            logger.info(f"Full attestation document length: {len(attestation_b64_raw)} chars")
            logger.info(f"Attestation document type check: {type(attestation_b64_raw)} - is string: {isinstance(attestation_b64_raw, str)}")
            logger.info(f"Encrypted datakey size: {len(encrypted_datakey)} bytes")
            logger.info(f"KMS Key ID: {kms_key_id}")
            
            try:
                # Note: boto3 KMS decrypt expects AttestationDocument as bytes, not base64 string
                decrypt_response = self.kms_client.decrypt(
                    CiphertextBlob=encrypted_datakey,
                    Recipient={
                        'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
                        'AttestationDocument': attestation_doc_with_key  # Use raw bytes, not base64
                    }
                )
                logger.info("KMS decrypt successful")
            except Exception as kms_error:
                logger.warning(f"KMS decrypt failed with error: {kms_error}")
                logger.warning(f"Error type: {type(kms_error).__name__}")
                if hasattr(kms_error, 'response'):
                    logger.warning(f"AWS Error Code: {kms_error.response.get('Error', {}).get('Code', 'Unknown')}")
                    logger.warning(f"AWS Error Message: {kms_error.response.get('Error', {}).get('Message', 'Unknown')}")
                raise Exception(f"KMS attestation document parsing failed: {str(kms_error)}")
            
            # Step 5: Decrypt CMS envelope with private key
            logger.info("Decrypting CMS envelope with private key")
            if 'CiphertextForRecipient' not in decrypt_response:
                raise Exception("No CiphertextForRecipient in KMS response")
            
            ciphertext_for_recipient = decrypt_response['CiphertextForRecipient']
            logger.info(f"CiphertextForRecipient type: {type(ciphertext_for_recipient)}")
            logger.info(f"CiphertextForRecipient length: {len(ciphertext_for_recipient)}")
            
            # CiphertextForRecipient is base64 encoded according to AWS docs
            if isinstance(ciphertext_for_recipient, str):
                cms_data = base64.b64decode(ciphertext_for_recipient)
            else:
                # boto3 might return it as bytes already
                cms_data = ciphertext_for_recipient
            
            logger.info(f"CMS data size after processing: {len(cms_data)} bytes")
            
            # Use OpenSSL to decrypt CMS envelope (fallback method)
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as priv_key_file:
                priv_key_file.write(private_key_pem)
                priv_key_file.flush()
                priv_key_file.close()
                
                try:
                    cms_decrypt_result = subprocess.run(['openssl', 'cms', '-decrypt', '-inform', 'DER', '-inkey', priv_key_file.name], input=cms_data, capture_output=True, timeout=30)  # nosec B603 B607
                    
                    logger.info(f"CMS decrypt return code: {cms_decrypt_result.returncode}")
                    if cms_decrypt_result.stderr:
                        logger.info(f"CMS decrypt stderr: {cms_decrypt_result.stderr.decode()}")
                    
                    if cms_decrypt_result.returncode != 0:
                        logger.warning(f"CMS decrypt failed: {cms_decrypt_result.stderr.decode()}")
                        raise Exception(f"CMS decrypt failed: {cms_decrypt_result.stderr.decode()}")
                    
                    if len(cms_decrypt_result.stdout) == 0:
                        raise Exception("CMS decrypt returned empty result")
                        
                finally:
                    os.unlink(priv_key_file.name)
            
            datakey = cms_decrypt_result.stdout
            logger.info(f"Successfully decrypted datakey, size: {len(datakey)} bytes")
            
            # Read the encrypted model file
            with open(encrypted_path, 'rb') as f:
                encrypted_model = f.read()
            
            logger.info(f"Read {len(encrypted_model)} bytes from encrypted file")
            
            # Step 6: Decrypt model with datakey (AES-256-GCM)
            logger.info("Decrypting model with datakey")
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Extract IV (first 12 bytes), ciphertext, and auth tag (last 16 bytes)
            iv = encrypted_model[:12]
            auth_tag = encrypted_model[-16:]
            ciphertext = encrypted_model[12:-16]
            
            # Decrypt with AES-256-GCM
            cipher = Cipher(algorithms.AES(datakey), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_model = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Step 7: Save decrypted model
            model_filename = os.path.basename(encrypted_path).replace('.encrypted', '').replace('.enc', '')
            model_path = os.path.join(self.models_dir, model_filename)
            
            logger.info(f"Saving decrypted model to {model_path}")
            with open(model_path, 'wb') as f:
                f.write(decrypted_model)
            
            # Clean up encrypted file
            os.unlink(encrypted_path)
            
            return {
                "status": "success",
                "model_path": model_path,
                "model_size": len(decrypted_model)
            }
            
        except Exception as e:
            error_msg = f"Failed to download and decrypt model: {e}"
            logger.warning(error_msg)
            debug_info = {
                "error_type": type(e).__name__,
                "step": "unknown"
            }
            
            if 'attestation_doc_with_key' in locals():
                debug_info.update({
                    "step": "KMS decrypt with attestation",
                    "attestation_size": len(attestation_doc_with_key),
                    "attestation_preview": attestation_b64_raw[:100] if 'attestation_b64_raw' in locals() else "N/A"
                })
            elif 'private_key_pem' in locals():
                debug_info["step"] = "RSA key generation"
            else:
                debug_info["step"] = "initialization"
                
            return {
                "status": "error", 
                "message": str(e),
                "debug_info": debug_info
            }
            

    
    
    def load_model_to_ollama(self, model_path: str, model_name: str, progress_callback=None) -> Dict[str, Any]:
        """Load model to Ollama and extend PCR15 with model hash"""
        try:
            # Get file size for progress calculation
            file_size = os.path.getsize(model_path)
            
            # Step 1: Calculate SHA-256 hash for Ollama (required)
            logger.info(f"Calculating SHA256 hash of {model_path}")
            sha256_hash = hashlib.sha256()
            bytes_processed = 0
            
            with open(model_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                    bytes_processed += len(chunk)
                    if progress_callback and file_size > 0:
                        progress = (bytes_processed / file_size) * 100
                        progress_callback('calculate_sha256', progress, bytes_processed, file_size)
            
            model_hash_sha256 = sha256_hash.hexdigest()
            logger.info(f"Model SHA256 hash: {model_hash_sha256}")
            
            # Step 2: Calculate SHA-384 hash for PCR15 extension
            logger.info(f"Calculating SHA384 hash of {model_path}")
            sha384_hash = hashlib.sha384()
            bytes_processed = 0
            
            with open(model_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha384_hash.update(chunk)
                    bytes_processed += len(chunk)
                    if progress_callback and file_size > 0:
                        progress = (bytes_processed / file_size) * 100
                        progress_callback('calculate_sha384', progress, bytes_processed, file_size)
            
            model_hash_sha384 = sha384_hash.hexdigest()
            logger.info(f"Model SHA384 hash: {model_hash_sha384}")
            
            # Step 3: Extend PCR15 with SHA-384 model hash
            logger.info("Extending PCR15 with SHA-384 model hash")
            self._extend_pcr15(model_hash_sha384)
            
            # Step 3: Upload blob using curl -T equivalent
            blob_url = f"{self.ollama_url}/api/blobs/sha256:{model_hash_sha256}"
            
            # Check if blob already exists
            check_response = requests.head(blob_url, timeout=30)
            if check_response.status_code == 200:
                logger.info("Model blob already exists in Ollama, skipping upload")
            else:
                logger.info("Uploading model blob to Ollama (curl -T equivalent)")
                
                # Get file size for progress tracking
                file_size = os.path.getsize(model_path)
                uploaded = 0
                
                class ProgressFile:
                    def __init__(self, file_path, callback):
                        self.file_path = file_path
                        self.callback = callback
                        self.uploaded = 0
                        self.total = os.path.getsize(file_path)
                        self._file = None
                    
                    def __enter__(self):
                        # File closed in exit block, context manager pattern
                        # nosemgrep: open-never-closed Message
                        self._file = open(self.file_path, 'rb')
                        return self
                    
                    def __exit__(self, exc_type, exc_val, exc_tb):
                        if self._file:
                            self._file.close()
                    
                    def read(self, size=-1):
                        chunk = self._file.read(size)
                        if chunk and self.callback:
                            self.uploaded += len(chunk)
                            progress = (self.uploaded / self.total) * 100
                            self.callback('upload_blob', progress, self.uploaded, self.total)
                        return chunk
                    
                    def __iter__(self):
                        return self
                    
                    def __next__(self):
                        chunk = self.read(8192)
                        if not chunk:
                            raise StopIteration
                        return chunk
                
                with ProgressFile(model_path, progress_callback) as progress_file:
                    blob_response = requests.post(
                        blob_url,
                        data=progress_file,
                        headers={'Content-Type': 'application/octet-stream'},
                        timeout=600
                    )
                
                if blob_response.status_code not in [200, 201]:
                    raise Exception(f"Failed to upload blob: HTTP {blob_response.status_code} - {blob_response.text}")
            
            # Step 4: Create model using the uploaded blob
            logger.info(f"Creating model '{model_name}' in Ollama")
            model_filename = os.path.basename(model_path)
            
            create_response = requests.post(
                f"{self.ollama_url}/api/create",
                json={
                    "model": model_name,
                    "files": {
                        model_filename: f"sha256:{model_hash_sha256}"
                    }
                },
                timeout=300
            )
            
            if create_response.status_code != 200:
                raise Exception(f"Failed to create model: {create_response.text}")
            
            logger.info(f"Successfully created model '{model_name}' in Ollama")
            
            # Clean up the decrypted model file after successful upload
            try:
                os.unlink(model_path)
                logger.info(f"Cleaned up temporary model file: {model_path}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up temporary model file {model_path}: {cleanup_error}")
            
            return {
                "status": "success",
                "model_name": model_name,
                "model_hash": model_hash_sha256,
                "model_hash_sha384": model_hash_sha384,
                "pcr15_extended": True
            }
            
        except Exception as e:
            logger.warning(f"Failed to load model to Ollama: {e}")
            return {"status": "error", "message": str(e)}
    
    def _extend_pcr15(self, model_hash_sha384: str):
        """Extend PCR15 with SHA-384 model hash using TPM"""
        try:
            # Use tpm2-tools to extend PCR15 with SHA-384 algorithm
            result = subprocess.run(['tpm2_pcrextend', f'15:sha384={model_hash_sha384}'], capture_output=True, text=True)  # nosec B603 B607
            
            if result.returncode != 0:
                raise Exception(f"PCR15 SHA-384 extend failed: {result.stderr}")
            
            logger.info(f"Successfully extended PCR15 with SHA-384 model hash: {model_hash_sha384}")
            
        except Exception as e:
            logger.warning(f"Failed to extend PCR15 with SHA-384: {e}")
            raise
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of loaded models"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=30)
            if response.status_code == 200:
                return {"status": "success", "models": response.json()}
            else:
                return {"status": "error", "message": "Failed to get model status"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def calculate_model_hash(self, model_path: str) -> Dict[str, Any]:
        """Calculate SHA-256 hash of model file"""
        try:
            logger.info(f"Calculating SHA256 hash of {model_path}")
            sha256_hash = hashlib.sha256()
            with open(model_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            model_hash = sha256_hash.hexdigest()
            logger.info(f"Model SHA256 hash: {model_hash}")
            
            return {
                "status": "success",
                "model_hash": model_hash
            }
            
        except Exception as e:
            logger.warning(f"Failed to calculate model hash: {e}")
            return {"status": "error", "message": str(e)}
    
    def extend_pcr15(self, model_hash: str) -> Dict[str, Any]:
        """Extend PCR15 with model hash using SHA-384"""
        try:
            # Convert SHA-256 hash to SHA-384 for PCR extension
            sha384_hash = hashlib.sha384(model_hash.encode()).hexdigest()
            
            # Use tpm2-tools to extend PCR15 with SHA-384 algorithm
            result = subprocess.run(['tpm2_pcrextend', f'15:sha384={sha384_hash}'], capture_output=True, text=True)  # nosec B603 B607
            
            if result.returncode != 0:
                raise Exception(f"PCR15 SHA-384 extend failed: {result.stderr}")
            
            logger.info(f"Successfully extended PCR15 with SHA-384 hash: {sha384_hash}")
            
            # Get current PCR15 value
            pcr_result = subprocess.run(['tpm2_pcrread', 'sha384:15'], capture_output=True, text=True)  # nosec B603 B607
            
            pcr_value = "unknown"
            if pcr_result.returncode == 0:
                # Parse PCR value from output
                lines = pcr_result.stdout.strip().split('\n')
                for line in lines:
                    if '15:' in line:
                        pcr_value = line.split(':', 1)[1].strip()
                        break
            
            return {
                "status": "success",
                "pcr_value": pcr_value,
                "model_hash": model_hash
            }
            
        except Exception as e:
            logger.warning(f"Failed to extend PCR15: {e}")
            return {"status": "error", "message": str(e)}
    
    def unload_model_from_ollama(self, model_name: str) -> Dict[str, Any]:
        """Unload model from Ollama"""
        try:
            logger.info(f"Unloading model '{model_name}' from Ollama")
            response = requests.delete(f"{self.ollama_url}/api/delete", json={"name": model_name}, timeout=30)
            
            if response.status_code == 200:
                logger.info(f"Successfully unloaded model '{model_name}'")
                return {"status": "success", "message": f"Model '{model_name}' unloaded"}
            else:
                error_msg = f"Failed to unload model: {response.text}"
                logger.warning(error_msg)
                return {"status": "error", "message": error_msg}
                
        except Exception as e:
            error_msg = f"Failed to unload model: {e}"
            logger.warning(error_msg)
            return {"status": "error", "message": error_msg}
