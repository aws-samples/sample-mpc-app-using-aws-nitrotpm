from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import httpx
import json
import asyncio
import os
import struct
import boto3
import logging
from tpm_client import TPMClient, parse_attestation_document
from model_manager import ModelManager
from model_owner_manager import ModelOwnerManager
from websocket_manager import websocket_manager
from certificate_parser import parse_certificate_chain
from attestation_validator import validate_attestation_document

logger = logging.getLogger(__name__)

def get_aws_region():
    """Get AWS region from IMDS"""
    import urllib3
    http = urllib3.PoolManager()
    token_response = http.request('PUT', 'http://169.254.169.254/latest/api/token', 
                                 headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})
    token = token_response.data.decode('utf-8')
    region_response = http.request('GET', 'http://169.254.169.254/latest/meta-data/placement/region',
                                  headers={'X-aws-ec2-metadata-token': token})
    return region_response.data.decode('utf-8')

app = FastAPI(title="Ollama Chat API", version="1.0.0")

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    # Add no-cache headers to all API responses
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[Message]

class ModelInfo(BaseModel):
    name: str
    digest: Optional[str] = None
    size: Optional[int] = None

@app.get("/models")
async def get_models():
    """Get list of available Ollama models with their SHA256 hashes"""
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            
            models = []
            for model in data.get("models", []):
                models.append(ModelInfo(
                    name=model.get("name", ""),
                    digest=model.get("digest", ""),
                    size=model.get("size", 0)
                ))
            
            return {"models": models}
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Failed to connect to Ollama: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/chat/stream")
async def chat_stream(request: ChatRequest):
    """Stream chat responses from Ollama in OpenAI-compatible format"""
    try:
        async def generate_stream():
            ollama_request = {
                "model": request.model,
                "messages": [{"role": msg.role, "content": msg.content} for msg in request.messages],
                "stream": True
            }
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                async with client.stream(
                    "POST",
                    f"{OLLAMA_BASE_URL}/api/chat",
                    json=ollama_request
                ) as response:
                    response.raise_for_status()
                    
                    async for line in response.aiter_lines():
                        if line.strip():
                            try:
                                ollama_data = json.loads(line)
                                
                                # Convert Ollama format to OpenAI format
                                openai_chunk = {
                                    "choices": [{
                                        "delta": {
                                            "content": ollama_data.get("message", {}).get("content", "")
                                        },
                                        "finish_reason": "stop" if ollama_data.get("done", False) else None
                                    }]
                                }
                                
                                yield f"data: {json.dumps(openai_chunk)}\n\n"
                                
                                if ollama_data.get("done", False):
                                    yield "data: [DONE]\n\n"
                                    break
                                    
                            except json.JSONDecodeError:
                                continue
        
        return StreamingResponse(
            generate_stream(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/event-stream",
            }
        )
        
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Failed to connect to Ollama: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            response.raise_for_status()
            return {"status": "healthy", "ollama": "connected"}
    except:
        return {"status": "unhealthy", "ollama": "disconnected"}

@app.get("/tpm/status")
async def get_tpm_status():
    """Get TPM device status"""
    tpm_client = TPMClient()
    
    # Test basic TPM communication
    communication_test = "failed"
    try:
        # Try a simple TPM command (GetCapability)
        command = struct.pack('>HII', 0x8001, 22, 0x0000017A)  # TPM2_CC_GetCapability
        command += struct.pack('>III', 0x00000006, 0x00000000, 1)  # capability, property, count
        
        with open(tpm_client.device_path, 'r+b', buffering=0) as tmp:
            tmp.write(command)
            tmp.flush()
            header = tmp.read(10)
            if len(header) == 10:
                _, size, response_code = struct.unpack('>HII', header)
                if response_code == 0:
                    communication_test = "success"
                else:
                    communication_test = f"error_0x{response_code:08x}"
    except Exception as e:
        communication_test = f"exception: {str(e)}"
    
    # Test NSM vendor command support
    nsm_test = "failed"
    try:
        # Try NSM vendor command with minimal structure
        command = struct.pack('>HII', 0x8001, 14, 0x20000001)  # ST_NO_SESSIONS, size, NSM command
        
        with open(tpm_client.device_path, 'r+b', buffering=0) as tmp:
            tmp.write(command)
            tmp.flush()
            response = tmp.read()
            if len(response) >= 10:
                _, size, response_code = struct.unpack('>HII', response[:10])
                if response_code == 0:
                    nsm_test = "supported"
                elif response_code == 0x143 or response_code == 0x000b0143:
                    nsm_test = "not_supported_on_this_instance"
                else:
                    nsm_test = f"error_0x{response_code:08x}"
    except Exception as e:
        nsm_test = f"exception: {str(e)}"
    
    return {
        "tpm_available": tpm_client.is_available(),
        "device_path": tpm_client.device_path,
        "communication_test": communication_test,
        "nsm_vendor_command_test": nsm_test
    }

@app.get("/tee/environment")
async def get_tee_environment():
    """Get TEE environment information from instance metadata"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Get IMDSv2 token
            token_response = await client.put(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
            )
            token_response.raise_for_status()
            token = token_response.text
            
            headers = {"X-aws-ec2-metadata-token": token}
            
            # Get instance identity document
            identity_response = await client.get(
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                headers=headers
            )
            identity_response.raise_for_status()
            identity_doc = identity_response.json()
            
            # Get IAM info if available
            iam_info = None
            try:
                iam_response = await client.get(
                    "http://169.254.169.254/latest/meta-data/iam/info",
                    headers=headers
                )
                if iam_response.status_code == 200:
                    iam_info = iam_response.json()
            except:  # nosec B110
                pass
            
            # Get instance type
            instance_type_response = await client.get(
                "http://169.254.169.254/latest/meta-data/instance-type",
                headers=headers
            )
            instance_type = instance_type_response.text if instance_type_response.status_code == 200 else "unknown"
            
            return {
                "status": "success",
                "instance_identity": identity_doc,
                "iam_info": iam_info,
                "instance_type": instance_type,
                "account_id": identity_doc.get("accountId"),
                "region": identity_doc.get("region"),
                "availability_zone": identity_doc.get("availabilityZone"),
                "instance_id": identity_doc.get("instanceId"),
                "image_id": identity_doc.get("imageId"),
                "architecture": identity_doc.get("architecture")
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get TEE environment info: {str(e)}")

@app.get("/tee/gpu")
async def get_gpu_info():
    """Get GPU information using nvidia-smi"""
    try:
        import subprocess  # nosec B404
        
        # Get comprehensive GPU info - static command list for security
        cmd = ["nvidia-smi", "--query-gpu=name,driver_version,memory.total,memory.used,memory.free,temperature.gpu,power.draw,power.limit,utilization.gpu,utilization.memory,pci.bus_id,uuid", "--format=csv,noheader,nounits"]
        # nosemgrep: dangerous-subprocess-use-audit
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)  # nosec B603 B607 B602
        
        if result.returncode != 0:
            return {
                "status": "error",
                "message": f"nvidia-smi command failed with return code {result.returncode}",
                "stderr": result.stderr,
                "stdout": result.stdout,
                "command": " ".join(cmd)
            }
        
        # Parse CSV output
        lines = result.stdout.strip().split('\n')
        gpus = []
        
        for i, line in enumerate(lines):
            if line.strip():
                values = [v.strip() for v in line.split(',')]
                if len(values) >= 12:
                    gpu_info = {
                        "gpu_id": i,
                        "name": values[0],
                        "driver_version": values[1],
                        "cuda_version": "N/A",
                        "memory_total_mb": values[2],
                        "memory_used_mb": values[3],
                        "memory_free_mb": values[4],
                        "temperature_c": values[5],
                        "power_draw_w": values[6],
                        "power_limit_w": values[7],
                        "utilization_gpu_percent": values[8],
                        "utilization_memory_percent": values[9],
                        "pci_bus_id": values[10],
                        "uuid": values[11]
                    }
                    gpus.append(gpu_info)
        
        return {
            "status": "success",
            "gpu_count": len(gpus),
            "gpus": gpus
        }
        
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "nvidia-smi command timed out"
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "message": "nvidia-smi not found - GPU drivers may not be installed"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get GPU info: {str(e)}"
        }

@app.get("/attestation")
async def get_attestation_document(nonce: str = None):
    """Get TPM attestation document with verified certificates"""
    tpm_client = TPMClient()
    
    if not tpm_client.is_available():
        raise HTTPException(status_code=503, detail="TPM device not available")
    
    try:
        nonce_bytes = nonce.encode() if nonce else None
        doc_bytes = tpm_client.get_attestation_document(nonce=nonce_bytes)
        parsed_doc = parse_attestation_document(doc_bytes)
        
        # Validate attestation document signature
        validation_result = validate_attestation_document(doc_bytes, nonce)
        attestation_signature_verified = validation_result.get("verified", False)
        
        # Debug logging
        logger.info(f"Attestation validation result: {validation_result}")
        logger.info(f"Signature verified: {attestation_signature_verified}")
        
        # Parse and verify certificate chain
        cert_chain = parse_certificate_chain(
            parsed_doc.get("raw_certificate", b""),
            parsed_doc.get("raw_cabundle", [])
        )
        
        # Remove raw bytes from response
        parsed_doc.pop("raw_certificate", None)
        parsed_doc.pop("raw_cabundle", None)
                
        return {
            "status": "success",
            "attestation_document": parsed_doc,
            "certificates": cert_chain.get("certificates", []),
            "certificate_chain_status": cert_chain.get("status", "unknown"),
            "root_verified": cert_chain.get("root_verified", False),
            "chain_verified": cert_chain.get("chain_verified", False),
            "chain_verification_error": cert_chain.get("chain_verification_error"),
            "attestation_signature_verified": attestation_signature_verified
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get attestation document: {str(e)}")

# Model management endpoints
model_manager = ModelManager()

class ModelDownloadRequest(BaseModel):
    bucket: str
    model_key: str
    datakey_key: str
    kms_key_id: str

class ModelUploadRequest(BaseModel):
    model_path: str
    bucket: str
    kms_key_id: str

class ModelLoadRequest(BaseModel):
    model_path: str
    model_name: str

@app.post("/models/download")
async def download_model(request: ModelDownloadRequest):
    """Download and decrypt model from S3 using KMS with attestation"""
    try:
        # Get attestation document
        tpm_client = TPMClient()
        attestation_doc = tpm_client.get_attestation_document()
        
        result = model_manager.download_and_decrypt_model(
            request.bucket,
            request.model_key,
            request.datakey_key,
            request.kms_key_id,
            attestation_doc
        )
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

@app.post("/models/upload")
async def upload_model(request: ModelUploadRequest):
    """Encrypt and upload model to S3"""
    try:
        result = model_manager.upload_encrypted_model(
            request.model_path,
            request.bucket,
            request.kms_key_id
        )
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post("/models/load")
async def load_model(request: ModelLoadRequest):
    """Load model to Ollama and extend PCR16"""
    try:
        result = model_manager.load_model_to_ollama(
            request.model_path,
            request.model_name
        )
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Load failed: {str(e)}")

@app.delete("/models/{model_name}")
async def unload_model(model_name: str):
    """Unload model from Ollama"""
    try:
        result = model_manager.unload_model_from_ollama(model_name)
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unload failed: {str(e)}")

@app.get("/models/status")
async def get_models_status():
    """Get status of loaded models"""
    return model_manager.get_model_status()

# KMS management endpoints
class KMSPolicyRequest(BaseModel):
    policy: str

@app.post("/kms/create-key")
async def create_kms_key():
    """Create a new KMS key"""
    try:
        region = get_aws_region()
        kms_client = boto3.client('kms', region_name=region)
        response = kms_client.create_key(
            Description='TPM Attestation Key for Secure Model Loading',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )
        return {"key_id": response['KeyMetadata']['KeyId']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create KMS key: {str(e)}")

@app.get("/kms/policy/{key_id}")
async def get_kms_policy(key_id: str):
    """Get KMS key policy"""
    try:
        region = get_aws_region()
        kms_client = boto3.client('kms', region_name=region)
        response = kms_client.get_key_policy(
            KeyId=key_id,
            PolicyName='default'
        )
        return {"policy": response['Policy']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get KMS policy: {str(e)}")

@app.put("/kms/policy/{key_id}")
async def update_kms_policy(key_id: str, request: KMSPolicyRequest):
    """Update KMS key policy"""
    try:
        region = get_aws_region()
        kms_client = boto3.client('kms', region_name=region)
        kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=request.policy
        )
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update KMS policy: {str(e)}")

# S3 management endpoints
@app.get("/s3/list/{bucket_name}")
async def list_s3_objects(bucket_name: str):
    """List objects in S3 bucket"""
    
    try:
        region = get_aws_region()
        s3_client = boto3.client('s3', region_name=region)
        response_data = s3_client.list_objects_v2(Bucket=bucket_name)
        
        objects = []
        for obj in response_data.get('Contents', []):
            objects.append({
                'key': obj['Key'],
                'size': obj['Size'],
                'last_modified': obj['LastModified'].isoformat()
            })
        
        return {'objects': objects}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list S3 objects: {str(e)}")

@app.delete("/s3/delete/{bucket_name}/{object_key:path}")
async def delete_s3_object(bucket_name: str, object_key: str):
    """Delete object from S3 bucket"""
    try:
        region = get_aws_region()
        s3_client = boto3.client('s3', region_name=region)
        s3_client.delete_object(Bucket=bucket_name, Key=object_key)
        return {'status': 'success', 'message': f'Object {object_key} deleted successfully'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete S3 object: {str(e)}")

# Model Owner Manager endpoints
model_owner_manager = ModelOwnerManager()

class ModelProcessRequest(BaseModel):
    model_name: str
    hf_repo: str
    kms_key_id: str
    bucket: str
    s3_path: str
    create_bucket: bool = False

@app.post("/model-owner/process")
async def process_model(request: ModelProcessRequest):
    """Process HF model: download, encrypt, upload to S3"""
    try:
        result = model_owner_manager.process_model(
            request.model_name,
            request.hf_repo,
            request.kms_key_id,
            request.bucket,
            request.s3_path,
            request.create_bucket
        )
        
        if result["status"] == "error":
            raise HTTPException(status_code=500, detail=result["message"])
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model processing failed: {str(e)}")

@app.websocket("/ws/model-loader/{client_id}")
async def model_loader_websocket(websocket: WebSocket, client_id: str):
    logger.info(f"Model Loader WebSocket connection attempt for client: {client_id}")
    await websocket_manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            logger.info(f"Received Model Loader WebSocket message: {message['type']} from {client_id}")
            
            if message["type"] == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue
            elif message["type"] == "load_model":
                logger.info(f"Starting model loading for {message['model_name']}")
                try:
                    # Send immediate acknowledgment
                    await websocket.send_text(json.dumps({
                        "type": "ack",
                        "message": "Load request received, starting processing..."
                    }))
                    
                    # Start async processing
                    task = asyncio.create_task(websocket_manager.load_model_async(
                        client_id,
                        message["bucket"],
                        message["model_key"],
                        message["datakey_key"],
                        message["kms_key_id"],
                        message["model_name"]
                    ))
                    
                    # Add error callback
                    def task_done_callback(task):
                        if task.exception():
                            logger.error(f"Model loading task failed for {client_id}: {task.exception()}")
                            asyncio.create_task(websocket_manager.send_message(client_id, {
                                "type": "error",
                                "message": f"Model loading failed: {str(task.exception())}"
                            }))
                    
                    task.add_done_callback(task_done_callback)
                    
                except Exception as e:
                    logger.error(f"Failed to start model loading for {client_id}: {e}")
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": f"Failed to start model loading: {str(e)}"
                    }))
                
    except WebSocketDisconnect:
        logger.info(f"Model Loader WebSocket disconnected: {client_id}")
        websocket_manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"Model Loader WebSocket error for {client_id}: {e}")
        websocket_manager.disconnect(client_id)

@app.websocket("/ws/model-owner/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    logger.info(f"WebSocket connection attempt for client: {client_id}")
    await websocket_manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            logger.info(f"Received WebSocket message: {message['type']} from {client_id}")
            
            if message["type"] == "ping":
                # Respond to keepalive ping
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue
            elif message["type"] == "process_model":
                logger.info(f"Starting model processing for {message['model_name']}")
                # Start async processing
                asyncio.create_task(websocket_manager.process_model_async(
                    client_id,
                    message["model_name"],
                    message["hf_repo"],
                    message["kms_key_id"],
                    message["bucket"],
                    message["s3_path"],
                    message.get("create_bucket", False)
                ))
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {client_id}")
        websocket_manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
        websocket_manager.disconnect(client_id)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)