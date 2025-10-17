import os
import tempfile
import subprocess  # nosec B404
import shutil
import requests
import boto3
import base64
import json
import logging
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class ModelOwnerManager:
    def __init__(self):
        from botocore.config import Config
        import urllib3
        
        # Get region from IMDS
        http = urllib3.PoolManager()
        token_response = http.request('PUT', 'http://169.254.169.254/latest/api/token', 
                                     headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})
        token = token_response.data.decode('utf-8')
        region_response = http.request('GET', 'http://169.254.169.254/latest/meta-data/placement/region',
                                      headers={'X-aws-ec2-metadata-token': token})
        region = region_response.data.decode('utf-8')
        
        # Configure timeouts for KMS to prevent hanging
        kms_config = Config(
            connect_timeout=10,
            read_timeout=30,
            retries={'max_attempts': 2}
        )
        
        self.s3_client = boto3.client('s3', region_name=region)
        self.kms_client = boto3.client('kms', region_name=region, config=kms_config)
        self.temp_dir = None
    
    def download_hf_model(self, model_name: str, hf_repo: str, progress_callback=None) -> Dict[str, Any]:
        """Download model from Hugging Face with progress tracking"""
        try:
            self.temp_dir = tempfile.mkdtemp(prefix='model_owner_')
            model_path = os.path.join(self.temp_dir, model_name)
            
            # Construct HF URL
            hf_url = f"https://huggingface.co/{hf_repo}/resolve/main/{model_name}?download=true"
            
            logger.info(f"Downloading {model_name} from {hf_url}")
            
            response = requests.get(hf_url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(model_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Send progress update
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress, downloaded, total_size)
            
            return {
                "status": "success",
                "model_path": model_path,
                "size": downloaded,
                "temp_dir": self.temp_dir
            }
            
        except Exception as e:
            logger.error(f"Failed to download model: {e}")
            if self.temp_dir:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            return {"status": "error", "message": str(e)}
    
    def generate_datakey(self, kms_key_id: str) -> Dict[str, Any]:
        """Generate datakey from KMS"""
        try:
            logger.info(f"Starting KMS datakey generation for key: {kms_key_id}")
            
            import time
            start_time = time.time()
            
            response = self.kms_client.generate_data_key(
                KeyId=kms_key_id,
                KeySpec='AES_256'
            )
            
            end_time = time.time()
            logger.info(f"KMS datakey generation completed in {end_time - start_time:.2f} seconds")
            
            plaintext_key = response['Plaintext']
            encrypted_key = response['CiphertextBlob']
            
            logger.info(f"Datakey generated successfully, plaintext length: {len(plaintext_key)}, encrypted length: {len(encrypted_key)}")
            
            return {
                "status": "success",
                "plaintext_key": plaintext_key,
                "encrypted_key": encrypted_key
            }
            
        except Exception as e:
            logger.error(f"Failed to generate datakey: {e}")
            return {"status": "error", "message": str(e)}
    
    def encrypt_model(self, model_path: str, plaintext_key: bytes) -> Dict[str, Any]:
        """Encrypt model with AES-256-GCM"""
        try:
            logger.info("Encrypting model with AES-256-GCM")
            
            # Generate random IV for GCM
            iv = os.urandom(12)  # 96-bit IV for GCM
            
            # Create cipher with GCM mode
            cipher = Cipher(algorithms.AES(plaintext_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            encrypted_path = model_path + '.enc'
            iv_path = os.path.join(os.path.dirname(model_path), 'iv.hex')
            
            # Encrypt file
            with open(model_path, 'rb') as infile, open(encrypted_path, 'wb') as outfile:
                # Write IV at the beginning
                outfile.write(iv)
                
                while True:
                    chunk = infile.read(8192)
                    if not chunk:
                        break
                    
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                
                outfile.write(encryptor.finalize())
                # Write authentication tag at the end
                outfile.write(encryptor.tag)
            
            # Write IV to separate file for compatibility
            with open(iv_path, 'w', encoding='utf-8') as f:
                f.write(iv.hex())
            
            return {
                "status": "success",
                "encrypted_path": encrypted_path,
                "iv_path": iv_path
            }
            
        except Exception as e:
            logger.error(f"Failed to encrypt model: {e}")
            return {"status": "error", "message": str(e)}
    
    def secure_delete_keys(self, temp_dir: str) -> Dict[str, Any]:
        """Securely delete plaintext key material"""
        try:
            logger.info("Securely deleting plaintext key material")
            
            # Find and shred key files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if any(keyword in file.lower() for keyword in ['key', 'plaintext']):
                        file_path = os.path.join(root, file)
                        # Overwrite with random data multiple times
                        if os.path.exists(file_path):
                            file_size = os.path.getsize(file_path)
                            with open(file_path, 'wb') as f:
                                for _ in range(3):  # 3 passes
                                    f.seek(0)
                                    f.write(os.urandom(file_size))
                                    f.flush()
                                    os.fsync(f.fileno())
                            os.remove(file_path)
            
            return {"status": "success"}
            
        except Exception as e:
            logger.error(f"Failed to secure delete: {e}")
            return {"status": "error", "message": str(e)}
    
    def upload_to_s3(self, encrypted_path: str, encrypted_key: bytes, iv_path: str, 
                     bucket: str, s3_path: str, model_name: str, progress_callback=None) -> Dict[str, Any]:
        """Upload encrypted model and keys to S3 with progress tracking"""
        try:
            import boto3.s3.transfer as s3transfer
            
            logger.info(f"Uploading to S3 bucket: {bucket}")
            
            # Create progress callback for S3 transfer
            class ProgressCallback:
                def __init__(self, callback):
                    self._callback = callback
                    self._seen_so_far = 0
                    self._total_size = 0
                
                def __call__(self, bytes_amount):
                    self._seen_so_far += bytes_amount
                    if self._callback and self._total_size > 0:
                        progress = (self._seen_so_far / self._total_size) * 100
                        self._callback(progress, self._seen_so_far, self._total_size)
            
            # Get file size for progress tracking
            file_size = os.path.getsize(encrypted_path)
            
            # Upload encrypted model with progress
            model_key = f"{s3_path}/{model_name}.enc"
            if progress_callback:
                callback_obj = ProgressCallback(progress_callback)
                callback_obj._total_size = file_size
                self.s3_client.upload_file(
                    encrypted_path, bucket, model_key,
                    Callback=callback_obj
                )
            else:
                self.s3_client.upload_file(encrypted_path, bucket, model_key)
            
            # Upload encrypted datakey
            datakey_key = f"{s3_path}/{model_name}.datakey.enc"
            self.s3_client.put_object(
                Bucket=bucket,
                Key=datakey_key,
                Body=encrypted_key
            )
            
            # Upload IV
            iv_key = f"{s3_path}/iv.hex"
            self.s3_client.upload_file(iv_path, bucket, iv_key)
            
            return {
                "status": "success",
                "model_key": model_key,
                "datakey_key": datakey_key,
                "iv_key": iv_key,
                "bucket": bucket
            }
            
        except Exception as e:
            logger.error(f"Failed to upload to S3: {e}")
            return {"status": "error", "message": str(e)}
    
    def create_s3_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Create S3 bucket with public access blocked"""
        try:
            logger.info(f"Creating S3 bucket: {bucket_name}")
            
            # Create bucket - let boto3 determine region from client configuration
            # Note: CreateBucketConfiguration is required for regions other than us-east-1
            # but we let boto3 handle this automatically based on the client's region
            try:
                # Try without LocationConstraint first (works for us-east-1)
                self.s3_client.create_bucket(Bucket=bucket_name)
            except Exception as e:
                # If that fails, try with the client's region as LocationConstraint
                import boto3.session
                session = boto3.session.Session()
                region = session.region_name
                if region and region != 'us-east-1':
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                else:
                    raise e
            
            # Block all public access
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            return {"status": "success", "bucket": bucket_name}
            
        except Exception as e:
            logger.error(f"Failed to create S3 bucket: {e}")
            return {"status": "error", "message": str(e)}
    
    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def process_model(self, model_name: str, hf_repo: str, kms_key_id: str, 
                     bucket: str, s3_path: str, create_bucket: bool = False) -> Dict[str, Any]:
        """Complete model processing pipeline"""
        try:
            results = {}
            
            # Step 1: Download model
            download_result = self.download_hf_model(model_name, hf_repo)
            if download_result["status"] == "error":
                return download_result
            results["download"] = download_result
            
            # Step 2: Generate datakey
            datakey_result = self.generate_datakey(kms_key_id)
            if datakey_result["status"] == "error":
                self.cleanup()
                return datakey_result
            results["datakey"] = datakey_result
            
            # Step 3: Encrypt model
            encrypt_result = self.encrypt_model(
                download_result["model_path"],
                datakey_result["plaintext_key"]
            )
            if encrypt_result["status"] == "error":
                self.cleanup()
                return encrypt_result
            results["encrypt"] = encrypt_result
            
            # Step 4: Create bucket if requested
            if create_bucket:
                bucket_result = self.create_s3_bucket(bucket)
                if bucket_result["status"] == "error":
                    self.cleanup()
                    return bucket_result
                results["bucket_creation"] = bucket_result
            
            # Step 5: Secure delete plaintext keys
            delete_result = self.secure_delete_keys(self.temp_dir)
            if delete_result["status"] == "error":
                self.cleanup()
                return delete_result
            results["secure_delete"] = delete_result
            
            # Step 6: Upload to S3
            upload_result = self.upload_to_s3(
                encrypt_result["encrypted_path"],
                datakey_result["encrypted_key"],
                encrypt_result["iv_path"],
                bucket,
                s3_path,
                model_name
            )
            if upload_result["status"] == "error":
                self.cleanup()
                return upload_result
            results["upload"] = upload_result
            
            # Cleanup
            self.cleanup()
            
            return {
                "status": "success",
                "results": results,
                "summary": {
                    "model_name": model_name,
                    "bucket": bucket,
                    "model_key": upload_result["model_key"],
                    "datakey_key": upload_result["datakey_key"],
                    "kms_key_id": kms_key_id
                }
            }
            
        except Exception as e:
            self.cleanup()
            logger.error(f"Model processing failed: {e}")
            return {"status": "error", "message": str(e)}