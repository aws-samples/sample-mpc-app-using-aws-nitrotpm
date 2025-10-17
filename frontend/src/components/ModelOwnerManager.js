import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  CircularProgress,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Chip,
  FormControlLabel,
  Checkbox,
  Paper,
  LinearProgress
} from '@mui/material';
import { 
  CloudDownload,
  Security,
  CloudUpload,
  Delete,
  CheckCircle,
  Error,
  Storage,
  Info
} from '@mui/icons-material';
import axios from 'axios';
import { useWebSocket } from '../contexts/WebSocketContext';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

const steps = [
  'Download from Hugging Face',
  'Generate KMS Data Key', 
  'Encrypt Model',
  'Create S3 Bucket',
  'Secure Delete Keys',
  'Upload to S3'
];

function ModelOwnerManager({ state = {}, setState }) {
  const { connect, send, disconnect, getConnection, updateHandlers } = useWebSocket();
  const clientIdRef = useRef(state.clientId || null);
  const processTimeoutRef = useRef(null);
  const pingIntervalRef = useRef(null);
  const bucketRef = useRef('');
  const [modelName, setModelName] = useState('mistral-7b-instruct-v0.2.Q4_K_M.gguf');
  const [hfRepo, setHfRepo] = useState('TheBloke/Mistral-7B-Instruct-v0.2-GGUF');
  const [kmsKeyId, setKmsKeyId] = useState('');
  const [bucket, setBucket] = useState('');
  
  // Update bucket ref whenever bucket state changes
  useEffect(() => {
    bucketRef.current = bucket;
  }, [bucket]);
  const [s3Path, setS3Path] = useState('models');
  const [createBucket, setCreateBucket] = useState(false);
  
  const [activeStep, setActiveStep] = useState(state.activeStep ?? -1);
  const [loading, setLoading] = useState(state.loading ?? false);
  const [error, setError] = useState(state.error ?? null);
  const [success, setSuccess] = useState(state.success ?? false);
  const [results, setResults] = useState(state.results ?? {});
  const [progressData, setProgressData] = useState(state.progressData ?? {});
  const [wsStatus, setWsStatus] = useState(state.wsStatus ?? 'disconnected');


  useEffect(() => {
    // Load KMS Key ID from session storage
    const savedKmsKey = sessionStorage.getItem('kmsKeyId');
    if (savedKmsKey) {
      setKmsKeyId(savedKmsKey);
    }
    
    // Load S3 bucket from session storage
    const savedBucket = sessionStorage.getItem('s3Bucket');
    if (savedBucket) {
      setBucket(savedBucket);
    }
  }, []);

  // Update parent state whenever local state changes
  React.useEffect(() => {
    if (setState) {
      setState({
        activeStep,
        loading,
        error,
        success,
        results,
        progressData,
        wsStatus,
        clientId: clientIdRef.current
      });
    }
  }, [activeStep, loading, error, success, results, progressData, wsStatus, setState]);

  // Check for existing connection on mount
  useEffect(() => {
    if (clientIdRef.current) {
      const existingConnection = getConnection(clientIdRef.current);
      if (existingConnection && existingConnection.readyState === WebSocket.OPEN) {
        console.log('Found existing WebSocket connection:', clientIdRef.current);
        setWsStatus('connected');
        
        // Update handlers for existing connection
        updateHandlers(clientIdRef.current, {
          onMessage: (event) => {
            const message = JSON.parse(event.data);
            console.log('WebSocket message received:', message);
            
            if (message.type === 'pong') return;
            
            switch (message.type) {
              case 'debug':
                console.log('Debug message:', message.message);
                break;
                
              case 'step_start':
                console.log('Step started:', message.step, message.message);
                setActiveStep(message.step);
                break;
                
              case 'step_complete':
                console.log('Step completed:', message.step, message.result);
                setResults(prev => ({ ...prev, [message.step]: message.result }));
                setProgressData(prev => ({ ...prev, [message.step]: null }));
                break;
                
              case 'progress':
                console.log('Progress received:', message);
                setProgressData(prev => ({
                  ...prev,
                  [message.step]: {
                    progress: message.progress,
                    downloaded: message.downloaded,
                    uploaded: message.uploaded,
                    total: message.total
                  }
                }));
                break;
                
              case 'complete':
                console.log('All processing complete');
                console.log(message.summary);
                if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
                if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
                setActiveStep(steps.length);
                setSuccess(true);
                setLoading(false);
                sessionStorage.setItem('modelDetails', JSON.stringify(message.summary));
                sessionStorage.setItem('s3Bucket', bucketRef.current);
                disconnect(clientIdRef.current);
                break;
                
              case 'error':
                console.error('WebSocket error');
                console.error(message.message);
                if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
                if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
                setError(message.message);
                setLoading(false);
                disconnect(clientIdRef.current);
                break;
            }
          }
        });
      }
    }
  }, [getConnection, updateHandlers, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (clientIdRef.current) {
        if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        // Don't disconnect WebSocket on unmount to keep it persistent
      }
    };
  }, []);

  const handleProcess = async () => {
    if (!modelName || !hfRepo || !kmsKeyId || !bucket) {
      setError('Please fill in all required fields');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(false);
    setActiveStep(-1);
    setResults({});
    setProgressData({});
    setWsStatus('connecting');

    // Generate unique client ID
    const clientId = Date.now().toString();
    clientIdRef.current = clientId;
    console.log('Starting process with client ID:', clientId);
    
    // Set timeout for the entire process (30 minutes)
    processTimeoutRef.current = setTimeout(() => {
      setError('Process timeout - check backend logs and S3 bucket for completion status');
      setLoading(false);
      setWsStatus('timeout');
    }, 30 * 60 * 1000);
    
    // Create persistent WebSocket connection
    connect(clientId, `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${API_BASE_URL}/ws/model-owner/${clientId}`, {
      onOpen: () => {
        console.log('WebSocket connected');
        setWsStatus('connected');
        
        // Start keepalive pings
        pingIntervalRef.current = setInterval(() => {
          send(clientId, JSON.stringify({ type: 'ping' }));
        }, 30000);
        
        // Send processing request
        const request = {
          type: 'process_model',
          model_name: modelName,
          hf_repo: hfRepo,
          kms_key_id: kmsKeyId,
          bucket: bucket,
          s3_path: s3Path,
          create_bucket: createBucket
        };
        console.log('Sending request:', request);
        send(clientId, JSON.stringify(request));
      },
      
      onMessage: (event) => {
        const message = JSON.parse(event.data);
        console.log('WebSocket message received:', message);
        
        if (message.type === 'pong') return;
        
        switch (message.type) {
          case 'debug':
            console.log('Debug message:', message.message);
            break;
            
          case 'step_start':
            console.log('Step started:', message.step, message.message);
            setActiveStep(message.step);
            break;
            
          case 'step_complete':
            console.log('Step completed:', message.step, message.result);
            setResults(prev => ({ ...prev, [message.step]: message.result }));
            setProgressData(prev => ({ ...prev, [message.step]: null }));
            break;
            
          case 'progress':
            console.log('Progress received:', message);
            setProgressData(prev => ({
              ...prev,
              [message.step]: {
                progress: message.progress,
                downloaded: message.downloaded,
                uploaded: message.uploaded,
                total: message.total
              }
            }));
            break;
            
          case 'complete':
            console.log('All processing complete');
            console.log(message.summary);
            if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
            if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
            setActiveStep(steps.length);
            setSuccess(true);
            setLoading(false);
            sessionStorage.setItem('modelDetails', JSON.stringify(message.summary));
            sessionStorage.setItem('s3Bucket', bucketRef.current);
            disconnect(clientId);
            break;
            
          case 'error':
            console.error('WebSocket error');
            console.error(message.message);
            if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
            if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
            setError(message.message);
            setLoading(false);
            disconnect(clientId);
            break;
        }
      },
      
      onError: (error) => {
        console.error('WebSocket error:', error);
        if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        setWsStatus('error');
        setError('WebSocket connection failed');
        setLoading(false);
      },
      
      onClose: (event) => {
        console.log('WebSocket closed:', event.code, event.reason);
        if (processTimeoutRef.current) clearTimeout(processTimeoutRef.current);
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        setWsStatus('disconnected');
        
        if (loading && !success && !error) {
          if (event.code !== 1000) {
            setError(`Connection closed unexpectedly (${event.code}). Processing may have completed - check S3 bucket: ${bucket}`);
          }
          setLoading(false);
        }
      }
    });
  };

  const getStepIcon = (stepIndex) => {
    if (activeStep > stepIndex) return <CheckCircle sx={{ color: '#4CAF50' }} />;
    if (activeStep === stepIndex && loading) return <CircularProgress size={24} />;
    if (error && activeStep <= stepIndex) return <Error sx={{ color: '#f44336' }} />;
    return null;
  };

  const getStepDetails = (stepIndex) => {
    const stepData = [
      { icon: <CloudDownload />, result: results[0] },
      { icon: <Security />, result: results[1] },
      { icon: <Security />, result: results[2] },
      { icon: <Storage />, result: results[3] },
      { icon: <Delete />, result: results[4] },
      { icon: <CloudUpload />, result: results[5] }
    ];

    return stepData[stepIndex];
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: '#4A4A4A' }}>
        Model Owner Manager
      </Typography>
      
      <Grid container spacing={3}>
        {/* Configuration Form */}
        <Grid item xs={12} md={6}>
          <Card sx={{ backgroundColor: '#E3F2FD' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                Model Configuration
              </Typography>
              
              <TextField
                fullWidth
                label="Model Name"
                value={modelName}
                onChange={(e) => setModelName(e.target.value)}
                margin="normal"
                placeholder="mistral-7b-instruct-v0.2.Q4_K_M.gguf"
              />
              
              <TextField
                fullWidth
                label="Hugging Face Repository"
                value={hfRepo}
                onChange={(e) => setHfRepo(e.target.value)}
                margin="normal"
                placeholder="TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
              />
              
              <TextField
                fullWidth
                label="KMS Key ID"
                value={kmsKeyId}
                onChange={(e) => {
                  setKmsKeyId(e.target.value);
                  sessionStorage.setItem('kmsKeyId', e.target.value);
                }}
                margin="normal"
                placeholder="From KMS Manager tab"
                helperText={sessionStorage.getItem('kmsKeyId') ? 'Loaded from session' : 'Enter or use KMS Manager under Seal Model weights TAB'}
              />
              
              <TextField
                fullWidth
                label="S3 Bucket"
                value={bucket}
                onChange={(e) => {
                  setBucket(e.target.value);
                  sessionStorage.setItem('s3Bucket', e.target.value);
                }}
                margin="normal"
                placeholder="my-secure-models"
                helperText={sessionStorage.getItem('s3Bucket') ? 'Loaded from session' : 'Enter bucket name'}
              />
              
              <TextField
                fullWidth
                label="S3 Path"
                value={s3Path}
                onChange={(e) => setS3Path(e.target.value)}
                margin="normal"
                placeholder="models"
              />
              
              <FormControlLabel
                control={
                  <Checkbox
                    checked={createBucket}
                    onChange={(e) => setCreateBucket(e.target.checked)}
                  />
                }
                label="Create S3 bucket if it doesn't exist"
                sx={{ mt: 1 }}
              />
              
              <Button
                variant="contained"
                onClick={handleProcess}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} /> : <Storage />}
                sx={{ 
                  mt: 2,
                  backgroundColor: '#2196F3',
                  '&:hover': { backgroundColor: '#1976D2' }
                }}
                fullWidth
              >
                {loading ? 'Processing...' : 'Process Model'}
              </Button>
              
              {/* Manual Status Check Button */}
              <Button
                variant="outlined"
onClick={() => {
                  // Check if files exist in S3 to determine completion
                  if (activeStep === 1 && !loading) {
                    setError('Processing may have completed. Check S3 bucket for encrypted files.');
                  }
                }}
                sx={{ mt: 1 }}
                fullWidth
                size="small"
              >
                Check Status
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Progress Stepper and Note */}
        <Grid item xs={12} md={6}>
          <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 2 }}>
            {/* Real-world Implementation Note */}
            <Card sx={{ backgroundColor: '#FFF8E1' }}>
              <CardContent sx={{ py: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 1 }}>
                  <Info sx={{ color: '#FF8F00', mr: 1.5, fontSize: 20, mt: 0.2 }} />
                  <Typography variant="subtitle2" sx={{ color: '#4A4A4A', fontWeight: 'bold' }}>
                    Real-world Implementation Note
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ color: '#666', lineHeight: 1.4, fontSize: '0.85rem' }}>
                  This sample app runs in the same AWS account for both owner and consumer, in real world, you would have additional functionality to publish to consumers with access modifiers and entitlements rather than simple S3 bucket access.
                </Typography>
              </CardContent>
            </Card>
            
            {/* Processing Progress */}
            <Card sx={{ backgroundColor: '#E8F5E8', flex: 1 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Processing Progress
                </Typography>
                
                {/* WebSocket Status */}
                <Box sx={{ mb: 2 }}>
                  <Chip 
                    label={`WebSocket: ${wsStatus}`}
                    color={wsStatus === 'connected' ? 'success' : wsStatus === 'error' ? 'error' : 'default'}
                    size="small"
                  />
                  <Chip 
                    label={`Active Step: ${activeStep}`}
                    color="primary"
                    size="small"
                    sx={{ ml: 1 }}
                  />
                </Box>
                

                
                <Stepper activeStep={activeStep} orientation="vertical">
                  {steps.map((label, index) => {
                    const stepDetails = getStepDetails(index);
                    return (
                      <Step key={label}>
                        <StepLabel 
                          icon={getStepIcon(index)}
                          error={error && activeStep === index}
                        >
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            {stepDetails.icon}
                            <Typography sx={{ ml: 1 }}>{label}</Typography>
                          </Box>
                        </StepLabel>
                        <StepContent>
                          <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                            {index === 0 && 'Downloading model from Hugging Face repository'}
                            {index === 1 && 'Generating encryption key from AWS KMS'}
                            {index === 2 && 'Encrypting model with AES-256-CBC'}
                            {index === 3 && 'Securely deleting plaintext key material'}
                            {index === 4 && 'Uploading encrypted model and keys to S3'}
                          </Typography>
                          
                          {/* Progress Bar for Download and Upload */}
                          {((index === 0 && progressData[0]) || (index === 4 && progressData[5])) && (
                            <Box sx={{ mb: 2 }}>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="caption">
                                  {index === 0 ? 'Download Progress' : 'Upload Progress'}
                                </Typography>
                                <Typography variant="caption">
                                  {index === 0 ? progressData[0]?.progress.toFixed(1) : progressData[5]?.progress.toFixed(1)}%
                                </Typography>
                              </Box>
                              <LinearProgress 
                                variant="determinate" 
                                value={index === 0 ? progressData[0]?.progress : progressData[5]?.progress} 
                                sx={{ height: 8, borderRadius: 4 }}
                              />
                              <Typography variant="caption" sx={{ mt: 0.5, display: 'block' }}>
                                {index === 0 
                                  ? `${(progressData[0]?.downloaded / 1024 / 1024).toFixed(1)} MB / ${(progressData[0]?.total / 1024 / 1024).toFixed(1)} MB`
                                  : `${(progressData[5]?.uploaded / 1024 / 1024).toFixed(1)} MB / ${(progressData[5]?.total / 1024 / 1024).toFixed(1)} MB`
                                }
                              </Typography>
                            </Box>
                          )}
                          
                          {stepDetails.result && (
                            <Box sx={{ mt: 1 }}>
                              {index === 0 && stepDetails.result.size && (
                                <Chip 
                                  label={`Size: ${(stepDetails.result.size / 1024 / 1024).toFixed(1)} MB`}
                                  size="small"
                                  sx={{ backgroundColor: '#C8E6C9' }}
                                />
                              )}
                              {index === 4 && stepDetails.result.model_key && (
                                <Box>
                                  <Chip 
                                    label={`Bucket: ${stepDetails.result.bucket}`}
                                    size="small"
                                    sx={{ backgroundColor: '#BBDEFB', mr: 1, mb: 1 }}
                                  />
                                  <Chip 
                                    label={`Model: ${stepDetails.result.model_key}`}
                                    size="small"
                                    sx={{ backgroundColor: '#FFE0B2', mb: 1 }}
                                  />
                                </Box>
                              )}
                            </Box>
                          )}
                        </StepContent>
                      </Step>
                    );
                  })}
                </Stepper>
              </CardContent>
            </Card>
          </Box>
        </Grid>

        {/* Results Summary */}
        {success && results && (
          <Grid item xs={12}>
            <Card sx={{ backgroundColor: '#E3F2FD' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Processing Complete
                </Typography>
                
                <Paper sx={{ p: 2, backgroundColor: '#F0F8FF' }}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" color="textSecondary">Model Name</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                        {modelName}
                      </Typography>
                    </Grid>
                    
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" color="textSecondary">S3 Location</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                        s3://{bucket}/{s3Path}/
                      </Typography>
                    </Grid>
                    
                    {results[5] && (
                      <>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="textSecondary">Encrypted Model Key</Typography>
                          <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                            {results[5].model_key}
                          </Typography>
                        </Grid>
                        
                        <Grid item xs={12}>
                          <Typography variant="body2" color="textSecondary">Data Key</Typography>
                          <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                            {results[5].datakey_key}
                          </Typography>
                        </Grid>
                      </>
                    )}
                  </Grid>
                </Paper>
                
                <Alert severity="success" sx={{ mt: 2 }}>
                  Model has been successfully encrypted and uploaded to S3. 
                  Details saved to session storage for use in other tabs.
                </Alert>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>

      {/* Status Messages */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
    </Box>
  );
}

export default ModelOwnerManager;