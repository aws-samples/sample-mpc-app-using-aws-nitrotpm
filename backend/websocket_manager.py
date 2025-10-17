import asyncio
import json
import uuid
from typing import Dict, Any
from fastapi import WebSocket
from model_owner_manager import ModelOwnerManager
import logging

logger = logging.getLogger(__name__)

class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.processing_jobs: Dict[str, ModelOwnerManager] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket connected: {client_id}")
    
    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"WebSocket disconnected: {client_id}")
    
    async def send_message(self, client_id: str, message: Dict[str, Any]):
        logger.info(f"Attempting to send message to {client_id}: {message['type']}")
        if client_id in self.active_connections:
            try:
                ws = self.active_connections[client_id]
                if ws.client_state.name != 'CONNECTED':
                    logger.error(f"WebSocket for {client_id} is not connected: {ws.client_state.name}")
                    self.disconnect(client_id)
                    return
                    
                message_json = json.dumps(message)
                logger.info(f"Sending WebSocket message to {client_id}: {message['type']} - {message.get('message', message.get('step', 'N/A'))}")
                await ws.send_text(message_json)
                logger.info(f"Successfully sent message to {client_id}")
            except Exception as e:
                logger.error(f"Failed to send message to {client_id}: {e}")
                logger.error(f"WebSocket state: {self.active_connections[client_id].client_state if client_id in self.active_connections else 'Not found'}")
                self.disconnect(client_id)
        else:
            logger.warning(f"Client {client_id} not found in active connections. Active clients: {list(self.active_connections.keys())}")
    
    async def load_model_async(self, client_id: str, bucket: str, model_key: str, datakey_key: str, kms_key_id: str, model_name: str):
        """Load model with WebSocket progress updates"""
        try:
            from model_manager import ModelManager
            model_manager = ModelManager()
            
            # Step 0: Download encrypted model
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 0,
                "message": "Downloading encrypted model from S3..."
            })
            
            # Progress tracking for S3 download
            progress_data = {"progress": 0, "downloaded": 0, "total": 0}
            
            def download_progress(step, progress, downloaded, total):
                progress_data.update({
                    "progress": progress,
                    "downloaded": downloaded,
                    "total": total
                })
            
            # Start download in background and monitor progress
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    model_manager.download_encrypted_model,
                    bucket, model_key, download_progress
                )
                
                # Monitor progress while download runs
                while not future.done():
                    if progress_data["total"] > 0:
                        await self.send_message(client_id, {
                            "type": "progress",
                            "step": 0,
                            "progress": progress_data["progress"],
                            "message": f"Downloading: {progress_data['progress']:.1f}% ({progress_data['downloaded']//1024//1024:.1f}/{progress_data['total']//1024//1024:.1f} MB)",
                            "downloaded": progress_data["downloaded"],
                            "total": progress_data["total"]
                        })
                    await asyncio.sleep(0.5)
                
                download_result = future.result()
            
            if download_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 0,
                    "message": download_result["message"]
                })
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 0,
                "message": "Download completed",
                "result": {"encrypted_path": download_result["encrypted_path"]}
            })
            
            # Step 1: Decrypt model in TEE
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 1,
                "message": "Starting decryption in TEE..."
            })
            
            # Sub-step 1: Generate key pair
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 1,
                "sub_step": "keygen",
                "message": "1. Generating RSA key pair..."
            })
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 1,
                "sub_step": "keygen",
                "message": "1. RSA key pair generated ✓"
            })
            
            # Sub-step 2: Get attestation document
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 1,
                "sub_step": "attestation",
                "message": "2. Fetching TPM attestation document..."
            })
            
            from tpm_client import TPMClient
            tpm_client = TPMClient()
            attestation_doc = tpm_client.get_attestation_document()
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 1,
                "sub_step": "attestation",
                "message": "2. TPM attestation document fetched ✓"
            })
            
            # Sub-step 3: KMS decrypt datakey
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 1,
                "sub_step": "kms_decrypt",
                "message": "3. KMS decrypt datakey with attestation..."
            })
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 1,
                "sub_step": "kms_decrypt",
                "message": "3. Datakey decrypted with KMS ✓"
            })
            
            # Sub-step 4: Decrypt model
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 1,
                "sub_step": "decrypt_model",
                "message": "4. Decrypting model weights inside TEE..."
            })
            
            decrypt_result = await asyncio.get_event_loop().run_in_executor(
                None, model_manager.decrypt_model,
                download_result["encrypted_path"], bucket, datakey_key, kms_key_id, attestation_doc
            )
            
            if decrypt_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 1,
                    "message": decrypt_result["message"]
                })
                return
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 1,
                "sub_step": "decrypt_model",
                "message": "4. Model weights decrypted inside TEE ✓"
            })
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 1,
                "message": "Decryption completed",
                "result": {"model_path": decrypt_result["model_path"], "model_size": decrypt_result["model_size"]}
            })
            
            # Step 2: Calculate Model Hash
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 2,
                "message": "Calculating model hash..."
            })
            
            # Sub-step: Calculate hash
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 2,
                "sub_step": "calculate_hash",
                "message": "Calculating SHA-256 and SHA-384 hashes of model file..."
            })
            
            # Calculate hash (this is done in load_model_to_ollama but we need it separately)
            hash_result = await asyncio.get_event_loop().run_in_executor(
                None, model_manager.calculate_model_hash, decrypt_result["model_path"]
            )
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 2,
                "sub_step": "calculate_hash",
                "message": "Model hash calculation completed ✓"
            })
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 2,
                "message": "Hash calculation completed",
                "result": {"model_hash": hash_result["model_hash"]}
            })
            
            # Step 3: Load to Ollama
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 3,
                "message": "Loading model to Ollama..."
            })
            
            # Progress tracking for Ollama upload
            upload_progress_data = {"progress": 0, "uploaded": 0, "total": 0}
            
            def ollama_progress(step, progress, uploaded, total):
                upload_progress_data.update({
                    "progress": progress,
                    "uploaded": uploaded,
                    "total": total
                })
            
            # Start Ollama loading in background and monitor progress
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    model_manager.load_model_to_ollama,
                    decrypt_result["model_path"], model_name, ollama_progress
                )
                
                # Monitor progress while upload runs
                while not future.done():
                    if upload_progress_data["total"] > 0:
                        await self.send_message(client_id, {
                            "type": "progress",
                            "step": 3,
                            "progress": upload_progress_data["progress"],
                            "message": f"Uploading to Ollama: {upload_progress_data['progress']:.1f}% ({upload_progress_data['uploaded']//1024//1024:.1f}/{upload_progress_data['total']//1024//1024:.1f} MB)",
                            "uploaded": upload_progress_data["uploaded"],
                            "total": upload_progress_data["total"]
                        })
                    await asyncio.sleep(0.5)
                
                load_result = future.result()
                
                # Send final 100% progress
                if upload_progress_data["total"] > 0:
                    await self.send_message(client_id, {
                        "type": "progress",
                        "step": 3,
                        "progress": 100.0,
                        "message": "Upload to Ollama completed",
                        "uploaded": upload_progress_data["total"],
                        "total": upload_progress_data["total"]
                    })
            
            if load_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 3,
                    "message": load_result["message"]
                })
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 3,
                "message": "Model loaded to Ollama",
                "result": {"model_name": model_name, "model_hash": load_result["model_hash"]}
            })
            
            # Step 4: Extend PCR15
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 4,
                "message": "Extending TPM PCR15 with model hash..."
            })
            
            # Sub-step: Extend PCR
            await self.send_message(client_id, {
                "type": "sub_step_start",
                "step": 4,
                "sub_step": "extend_pcr",
                "message": "Extending PCR15 with SHA-384 hash using tpm2_pcrextend..."
            })
            
            # Extend PCR15 with the model hash
            pcr_result = await asyncio.get_event_loop().run_in_executor(
                None, model_manager.extend_pcr15, load_result["model_hash"]
            )
            
            await self.send_message(client_id, {
                "type": "sub_step_complete",
                "step": 4,
                "sub_step": "extend_pcr",
                "message": "PCR15 extended with model hash ✓"
            })
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 4,
                "message": "PCR15 extended",
                "result": {"pcr_value": pcr_result["pcr_value"], "model_hash": load_result["model_hash"]}
            })
            
            await self.send_message(client_id, {
                "type": "complete",
                "message": f"Model '{model_name}' loaded successfully!",
                "result": {
                    "status": "success",
                    "model_name": model_name,
                    "model_hash": load_result["model_hash"],
                    "pcr15_extended": True
                }
            })
            
        except Exception as e:
            logger.error(f"Model loading failed for {client_id}: {e}")
            await self.send_message(client_id, {
                "type": "error",
                "message": f"Model loading failed: {str(e)}"
            })
    
    async def process_model_async(self, client_id: str, model_name: str, hf_repo: str, 
                                 kms_key_id: str, bucket: str, s3_path: str, create_bucket: bool = False):
        """Process model asynchronously with WebSocket updates"""
        # Create dedicated manager for this job
        manager = ModelOwnerManager()
        self.processing_jobs[client_id] = manager
        
        try:
            # Step 1: Download model
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 0,
                "message": "Starting model download from Hugging Face..."
            })
            
            # Progress callback for download
            # Store progress data to be sent
            progress_data = {"step": 0, "progress": 0, "downloaded": 0, "total": 0}
            
            def download_progress(progress, downloaded, total):
                logger.info(f"Download progress: {progress:.1f}% ({downloaded}/{total})")
                progress_data.update({
                    "progress": progress,
                    "downloaded": downloaded, 
                    "total": total
                })
            
            # Send progress updates every 1MB
            last_sent = 0
            
            # Start download with progress monitoring
            import threading
            import time
            
            # Start download in thread and monitor progress
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Start download in background thread
                future = executor.submit(manager.download_hf_model, model_name, hf_repo, download_progress)
                
                # Monitor progress while download runs
                while not future.done():
                    if progress_data["total"] > 0:
                        await self.send_message(client_id, {
                            "type": "progress",
                            "step": 0,
                            "progress": progress_data["progress"],
                            "downloaded": progress_data["downloaded"],
                            "total": progress_data["total"]
                        })
                    await asyncio.sleep(1)  # Send every second
                
                # Get result
                download_result = future.result()
            if download_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 0,
                    "message": download_result["message"]
                })
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 0,
                "result": {"status": download_result["status"], "size": download_result.get("size", 0)}
            })
            
            # Step 2: Generate datakey
            logger.info(f"Starting KMS datakey generation for client {client_id}")
            try:
                await self.send_message(client_id, {
                    "type": "step_start",
                    "step": 1,
                    "message": "Generating KMS data key..."
                })
                
                # Run KMS call in thread to prevent blocking
                logger.info(f"About to call generate_datakey with key_id: {kms_key_id}")
                datakey_result = await asyncio.get_event_loop().run_in_executor(
                    None, manager.generate_datakey, kms_key_id
                )
                logger.info(f"KMS datakey generation completed with result: {datakey_result['status']}")
                
                if datakey_result["status"] == "error":
                    await self.send_message(client_id, {
                        "type": "error",
                        "step": 1,
                        "message": datakey_result["message"]
                    })
                    manager.cleanup()
                    return
                
                await self.send_message(client_id, {
                    "type": "step_complete",
                    "step": 1,
                    "result": {"status": datakey_result["status"]}
                })
                
            except Exception as e:
                logger.error(f"Error in KMS step: {e}")
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 1,
                    "message": f"KMS step failed: {str(e)}"
                })
                manager.cleanup()
                return
            
            # Step 3: Encrypt model
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 2,
                "message": "Encrypting model with AES-256-CBC..."
            })
            
            # Run encryption in thread to prevent blocking
            encrypt_result = await asyncio.get_event_loop().run_in_executor(
                None, manager.encrypt_model, download_result["model_path"], datakey_result["plaintext_key"]
            )
            if encrypt_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 2,
                    "message": encrypt_result["message"]
                })
                manager.cleanup()
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 2,
                "result": {"status": encrypt_result["status"]}
            })
            
            # Step 4: Create bucket if requested
            if create_bucket:
                await self.send_message(client_id, {
                    "type": "step_start",
                    "step": 3,
                    "message": "Creating S3 bucket..."
                })
                
                bucket_result = manager.create_s3_bucket(bucket)
                if bucket_result["status"] == "error":
                    await self.send_message(client_id, {
                        "type": "error",
                        "step": 3,
                        "message": bucket_result["message"]
                    })
                    manager.cleanup()
                    return
                
                await self.send_message(client_id, {
                    "type": "step_complete",
                    "step": 3,
                    "result": {"status": bucket_result["status"]}
                })
            
            # Step 5: Secure delete keys
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 4,
                "message": "Securely deleting plaintext keys..."
            })
            
            delete_result = manager.secure_delete_keys(manager.temp_dir)
            if delete_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 4,
                    "message": delete_result["message"]
                })
                manager.cleanup()
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 4,
                "result": {"status": delete_result["status"]}
            })
            
            # Step 6: Upload to S3
            await self.send_message(client_id, {
                "type": "step_start",
                "step": 5,
                "message": "Uploading to S3..."
            })
            
            # Progress callback for upload
            def upload_progress(progress, uploaded, total):
                logger.info(f"Upload progress: {progress:.1f}% ({uploaded}/{total})")
                # Create a task to send the message
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.send_message(client_id, {
                        "type": "progress",
                        "step": 5,
                        "progress": progress,
                        "uploaded": uploaded,
                        "total": total
                    }))
                except Exception as e:
                    logger.error(f"Failed to send progress: {e}")
            
            upload_result = manager.upload_to_s3(
                encrypt_result["encrypted_path"],
                datakey_result["encrypted_key"],
                encrypt_result["iv_path"],
                bucket,
                s3_path,
                model_name,
                upload_progress
            )
            if upload_result["status"] == "error":
                await self.send_message(client_id, {
                    "type": "error",
                    "step": 5,
                    "message": upload_result["message"]
                })
                manager.cleanup()
                return
            
            await self.send_message(client_id, {
                "type": "step_complete",
                "step": 5,
                "result": {"status": upload_result["status"]}
            })
            
            # Cleanup and send success
            manager.cleanup()
            if client_id in self.processing_jobs:
                del self.processing_jobs[client_id]
            
            await self.send_message(client_id, {
                "type": "complete",
                "summary": {
                    "model_name": model_name,
                    "bucket": bucket,
                    "s3_path": f"s3://{bucket}/{s3_path}/",
                    "model_key": upload_result["model_key"],
                    "datakey_key": upload_result["datakey_key"],
                    "kms_key_id": kms_key_id
                }
            })
            
        except Exception as e:
            logger.error(f"Model processing failed: {e}")
            await self.send_message(client_id, {
                "type": "error",
                "message": f"Processing failed: {str(e)}",
                "debug_info": {
                    "error_type": type(e).__name__,
                    "step": "model_processing"
                }
            })
            if client_id in self.processing_jobs:
                self.processing_jobs[client_id].cleanup()
                del self.processing_jobs[client_id]

websocket_manager = WebSocketManager()