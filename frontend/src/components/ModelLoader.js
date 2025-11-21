import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip,
  Grid,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse
} from '@mui/material';
import { CloudDownload, Security, PlayArrow, CheckCircle, Error, ExpandMore, ExpandLess, BugReport, Memory, LockOpen, Info, CloudUpload, ArrowForward } from '@mui/icons-material';
import axios from 'axios';
import { useWebSocket } from '../contexts/WebSocketContext';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

const steps = [
  { id: 0, title: 'Download Encrypted Model to TEE', icon: <CloudDownload /> },
  { id: 1, title: 'Decrypt Model in TEE', icon: <LockOpen /> },
  { id: 2, title: 'Calculate Model Hash', icon: <Security /> },
  { id: 3, title: 'Load to Ollama', icon: <CloudUpload /> },
  { id: 4, title: 'Extend PCR15', icon: <Memory /> }
];

function ModelLoader({ state = {}, setState = () => {} }) {
  const { connect, send, disconnect, getConnection, updateHandlers } = useWebSocket();
  
  const {
    bucket = '',
    modelKey = '',
    datakeyKey = '',
    kmsKeyId = '',
    modelName = '',
    processing = false,
    currentStep = -1,
    stepProgress = {},
    stepResults = {},
    subSteps = {},
    debugMessages = [],
    showDebug = false,
    error = null,
    success = false,
    clientId = null
  } = state;

  const updateState = (updates) => {
    if (typeof updates === 'function') {
      setState(updates);
    } else {
      setState(prev => ({ ...prev, ...updates }));
    }
  };

  const setBucket = (value) => {
    updateState({ bucket: value });
    localStorage.setItem('modelLoader_bucket', value);
  };
  const setModelKey = (value) => {
    updateState({ modelKey: value });
    localStorage.setItem('modelLoader_modelKey', value);
  };
  const setDatakeyKey = (value) => {
    updateState({ datakeyKey: value });
    localStorage.setItem('modelLoader_datakeyKey', value);
  };
  const setKmsKeyId = (value) => {
    updateState({ kmsKeyId: value });
    localStorage.setItem('modelLoader_kmsKeyId', value);
  };
  const setModelName = (value) => {
    updateState({ modelName: value });
    localStorage.setItem('modelLoader_modelName', value);
  };
  
  const clientIdRef = useRef(clientId);
  const pingIntervalRef = useRef(null);
  const progressScrollRef = useRef(null);
  const [loadedModels, setLoadedModels] = useState([]);
  const [modelExists, setModelExists] = useState(false);


  
  const handleWebSocketMessage = (message) => {
    console.log('Received message:', message);
    console.log('Current state before update:', { currentStep, processing, subSteps });
    
    updateState(prev => ({
      ...prev,
      debugMessages: [...prev.debugMessages, {
        timestamp: new Date().toLocaleTimeString(),
        type: message.type,
        message: message.message || JSON.stringify(message)
      }]
    }));
    
    // Debug sub-step messages
    if (message.type === 'sub_step_start' || message.type === 'sub_step_complete') {
      console.log('Sub-step message:', message.type, 'Step:', message.step, 'Sub-step:', message.sub_step, 'Message:', message.message);
    }
    
    switch (message.type) {
      case 'step_start':
        updateState(prev => {
          // Clear progress data for previous step when new step starts
          const newStepProgress = { ...prev.stepProgress };
          if (message.step > 0 && newStepProgress[message.step - 1]) {
            newStepProgress[message.step - 1] = {
              ...newStepProgress[message.step - 1],
              progress: undefined
            };
          }
          
          return {
            ...prev,
            currentStep: message.step,
            stepProgress: {
              ...newStepProgress,
              [message.step]: { status: 'active', message: message.message, progress: 0 }
            }
          };
        });
        // Auto-scroll to current step
        setTimeout(() => {
          if (progressScrollRef.current) {
            const activeStepElement = progressScrollRef.current.querySelector(`[data-step="${message.step}"]`);
            if (activeStepElement) {
              activeStepElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
          }
        }, 100);
        break;
        
      case 'sub_step_start':
        console.log('Processing sub_step_start for step', message.step, 'sub_step', message.sub_step);
        updateState(prev => {
          const currentStepSubSteps = prev.subSteps[message.step] || {};
          const newSubSteps = {
            ...prev.subSteps,
            [message.step]: {
              ...currentStepSubSteps,
              [message.sub_step]: { 
                status: 'active', 
                message: message.message,
                startTime: Date.now()
              }
            }
          };
          console.log('Updated subSteps:', newSubSteps);
          return {
            ...prev,
            subSteps: newSubSteps
          };
        });
        break;
        
      case 'sub_step_complete':
        console.log('Processing sub_step_complete for step', message.step, 'sub_step', message.sub_step);
        updateState(prev => {
          const currentStepSubSteps = prev.subSteps[message.step] || {};
          const existingSubStep = currentStepSubSteps[message.sub_step] || {};
          const duration = existingSubStep.startTime ? Date.now() - existingSubStep.startTime : 0;
          
          const newSubSteps = {
            ...prev.subSteps,
            [message.step]: {
              ...currentStepSubSteps,
              [message.sub_step]: { 
                status: 'completed', 
                message: message.message,
                duration: duration
              }
            }
          };
          console.log('Updated subSteps:', newSubSteps);
          return {
            ...prev,
            subSteps: newSubSteps
          };
        });
        break;
        
      case 'progress':
        updateState(prev => {
          const currentStepProgress = prev.stepProgress[message.step] || {};
          
          // Handle sub-step progress
          if (message.sub_step) {
            const currentStepSubSteps = prev.subSteps[message.step] || {};
            return {
              ...prev,
              stepProgress: {
                ...prev.stepProgress,
                [message.step]: {
                  ...currentStepProgress,
                  message: message.message
                }
              },
              subSteps: {
                ...prev.subSteps,
                [message.step]: {
                  ...currentStepSubSteps,
                  [message.sub_step]: {
                    ...currentStepSubSteps[message.sub_step],
                    status: 'active',
                    progress: message.progress,
                    message: message.message,
                    processed: message.processed,
                    total: message.total
                  }
                }
              }
            };
          } else {
            // Regular step progress
            return {
              ...prev,
              stepProgress: {
                ...prev.stepProgress,
                [message.step]: {
                  ...currentStepProgress,
                  progress: message.progress,
                  message: message.message,
                  downloaded: message.downloaded,
                  total: message.total
                }
              }
            };
          }
        });
        break;
        
      case 'step_complete':
        updateState(prev => {
          // Clear any active sub-steps when step completes
          const newSubSteps = { ...prev.subSteps };
          if (newSubSteps[message.step]) {
            Object.keys(newSubSteps[message.step]).forEach(subStepKey => {
              if (newSubSteps[message.step][subStepKey].status === 'active') {
                newSubSteps[message.step][subStepKey] = {
                  ...newSubSteps[message.step][subStepKey],
                  status: 'completed'
                };
              }
            });
          }
          
          return {
            ...prev,
            stepProgress: {
              ...prev.stepProgress,
              [message.step]: { status: 'completed', message: message.message || 'Completed', progress: undefined }
            },
            stepResults: {
              ...prev.stepResults,
              [message.step]: message.result
            },
            subSteps: newSubSteps
          };
        });
        break;
        
      case 'error':
        updateState(prev => ({
          ...prev,
          error: message.message,
          processing: false,
          stepProgress: {
            ...prev.stepProgress,
            [message.step]: { status: 'error', message: message.message, progress: 0 }
          }
        }));
        break;
        
      case 'complete':
        updateState(prev => {
          // Clear any remaining active sub-steps
          const newSubSteps = { ...prev.subSteps };
          Object.keys(newSubSteps).forEach(stepKey => {
            Object.keys(newSubSteps[stepKey]).forEach(subStepKey => {
              if (newSubSteps[stepKey][subStepKey].status === 'active') {
                newSubSteps[stepKey][subStepKey] = {
                  ...newSubSteps[stepKey][subStepKey],
                  status: 'completed'
                };
              }
            });
          });
          
          return {
            ...prev,
            success: true,
            processing: false,
            currentStep: -1,
            subSteps: newSubSteps
          };
        });
        break;
    }
  };
  
  const fetchLoadedModels = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/models?_t=${Date.now()}`);
      setLoadedModels(response.data.models || []);
    } catch (err) {
      console.log('Could not fetch loaded models');
    }
  };

  useEffect(() => {
    // Load from localStorage first
    const savedBucket = localStorage.getItem('modelLoader_bucket');
    const savedModelKey = localStorage.getItem('modelLoader_modelKey');
    const savedDatakeyKey = localStorage.getItem('modelLoader_datakeyKey');
    const savedKmsKeyId = localStorage.getItem('modelLoader_kmsKeyId');
    const savedModelName = localStorage.getItem('modelLoader_modelName');
    
    if (savedBucket) updateState({ bucket: savedBucket });
    if (savedModelKey) updateState({ modelKey: savedModelKey });
    if (savedDatakeyKey) updateState({ datakeyKey: savedDatakeyKey });
    if (savedKmsKeyId) updateState({ kmsKeyId: savedKmsKeyId });
    if (savedModelName) updateState({ modelName: savedModelName });
    
    // Load KMS Key ID from Model Owner Manager (fallback)
    const sessionKmsKey = sessionStorage.getItem('kmsKeyId');
    if (sessionKmsKey && !savedKmsKeyId) {
      updateState({ kmsKeyId: sessionKmsKey });
      localStorage.setItem('modelLoader_kmsKeyId', sessionKmsKey);
    }
    
    // Load model details from Model Owner Manager if available (fallback)
    const modelDetails = sessionStorage.getItem('modelDetails');
    if (modelDetails && !savedBucket) {
      try {
        const details = JSON.parse(modelDetails);
        if (details.bucket) {
          updateState({ bucket: details.bucket });
          localStorage.setItem('modelLoader_bucket', details.bucket);
        }
        if (details.model_key) {
          updateState({ modelKey: details.model_key });
          localStorage.setItem('modelLoader_modelKey', details.model_key);
        }
        if (details.datakey_key) {
          updateState({ datakeyKey: details.datakey_key });
          localStorage.setItem('modelLoader_datakeyKey', details.datakey_key);
        }
        if (details.kms_key_id && !savedKmsKeyId) {
          updateState({ kmsKeyId: details.kms_key_id });
          localStorage.setItem('modelLoader_kmsKeyId', details.kms_key_id);
        }
        if (details.model_name && !savedModelName) {
          const modelName = details.model_name.replace('.gguf', '-secure');
          updateState({ modelName });
          localStorage.setItem('modelLoader_modelName', modelName);
        }
      } catch (e) {
        console.log('Could not parse model details from session storage');
      }
    }
    
    fetchLoadedModels();
  }, []);

  // Check if model name exists in loaded models
  useEffect(() => {
    const exists = loadedModels.some(model => {
      // Remove tag from model name for comparison (e.g., 'model:latest' -> 'model')
      const modelBaseName = model.name.split(':')[0];
      return modelBaseName === modelName || model.name === modelName;
    });
    setModelExists(exists);
  }, [modelName, loadedModels]);

  // Check for existing connection on mount
  useEffect(() => {
    if (clientIdRef.current) {
      const existingConnection = getConnection(clientIdRef.current);
      if (existingConnection && existingConnection.readyState === WebSocket.OPEN) {
        console.log('Found existing Model Loader WebSocket connection:', clientIdRef.current);
        
        // Update handlers for existing connection
        updateHandlers(clientIdRef.current, {
          onMessage: (event) => {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
          }
        });
      }
    }
  }, [getConnection, updateHandlers]);

  const resetState = () => {
    console.log('Resetting state, clearing subSteps');
    updateState({
      currentStep: -1,
      processing: false,
      error: null,
      success: false,
      stepResults: {},
      stepProgress: {},
      subSteps: {},
      debugMessages: []
    });
  };

  const handleLoadModel = () => {
    if (!bucket || !modelKey || !datakeyKey || !kmsKeyId || !modelName) {
      updateState({ error: 'Please fill in all fields' });
      return;
    }

    if (modelExists) {
      updateState({ error: 'Model with this name is already loaded' });
      return;
    }

    // Clean up any existing WebSocket connection and timers
    if (clientIdRef.current) {
      console.log('Disconnecting previous WebSocket connection:', clientIdRef.current);
      disconnect(clientIdRef.current);
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }
    }

    resetState();
    updateState({ processing: true });

    // Always generate a new unique client ID for each load attempt
    clientIdRef.current = `loader-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    updateState({ clientId: clientIdRef.current });

    // Set timeout for stuck connections
    const timeoutId = setTimeout(() => {
      updateState({ 
        error: 'Connection timeout - backend may be stuck. Please try again.',
        processing: false 
      });
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
    }, 30000); // 30 second timeout

    // Create persistent WebSocket connection
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.host;
    
    console.log('Attempting to connect WebSocket for client:', clientIdRef.current);
    
    connect(clientIdRef.current, `${wsProtocol}//${wsHost}${API_BASE_URL}/ws/model-loader/${clientIdRef.current}`, {
      onOpen: () => {
        console.log('Model Loader WebSocket connected, sending load request');
        
        // Start keepalive pings
        pingIntervalRef.current = setInterval(() => {
          send(clientIdRef.current, JSON.stringify({ type: 'ping' }));
        }, 30000);
        
        // Small delay to ensure connection is fully established
        setTimeout(() => {
          const message = {
            type: 'load_model',
            bucket,
            model_key: modelKey,
            datakey_key: datakeyKey,
            kms_key_id: kmsKeyId,
            model_name: modelName
          };
          console.log('Sending load_model message:', message);
          send(clientIdRef.current, JSON.stringify(message));
        }, 100);
      },
      
      onMessage: (event) => {
        const message = JSON.parse(event.data);
        // Clear timeout on any message received
        clearTimeout(timeoutId);
        handleWebSocketMessage(message);
      },
      
      onError: (error) => {
        console.error('Model Loader WebSocket error:', error);
        clearTimeout(timeoutId);
        updateState({ 
          error: 'WebSocket connection failed. Please try again.',
          processing: false 
        });
      },
      
      onClose: (event) => {
        console.log('Model Loader WebSocket closed:', event.code, event.reason);
        clearTimeout(timeoutId);
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
        }
        
        // If connection closed unexpectedly during processing, show error
        if (processing && event.code !== 1000) {
          updateState({ 
            error: 'Connection lost during processing. Please try again.',
            processing: false 
          });
        }
      }
    });
  };

  const getStepIcon = (stepIndex) => {
    const progress = stepProgress[stepIndex];
    if (progress?.status === 'completed') return <CheckCircle sx={{ color: '#4CAF50' }} />;
    if (progress?.status === 'active') return <CircularProgress size={24} />;
    if (progress?.status === 'error') return <Error sx={{ color: '#f44336' }} />;
    return steps[stepIndex]?.icon || null;
  };

  const getStepStatus = (stepIndex) => {
    const progress = stepProgress[stepIndex];
    return progress?.status || 'inactive';
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: '#4A4A4A' }}>
        Secure Model Loader
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
                label="S3 Bucket"
                value={bucket}
                onChange={(e) => setBucket(e.target.value)}
                margin="normal"
                placeholder="my-secure-models"
              />
              
              <TextField
                fullWidth
                label="Encrypted Model Key"
                value={modelKey}
                onChange={(e) => setModelKey(e.target.value)}
                margin="normal"
                placeholder="mistral.gguf.encrypted"
              />
              
              <TextField
                fullWidth
                label="Encrypted Datakey Key"
                value={datakeyKey}
                onChange={(e) => setDatakeyKey(e.target.value)}
                margin="normal"
                placeholder="mistral.gguf.datakey"
              />
              
              <TextField
                fullWidth
                label="KMS Key ID"
                value={kmsKeyId}
                onChange={(e) => setKmsKeyId(e.target.value)}
                margin="normal"
                placeholder="arn:aws:kms:us-east-1:123456789012:key/..."
              />
              
              <TextField
                fullWidth
                label="Model Name"
                value={modelName}
                onChange={(e) => setModelName(e.target.value)}
                margin="normal"
                placeholder="mistral-secure"
                error={modelExists}
                helperText={modelExists ? 'Model with this name is already loaded' : ''}
              />
              
              {modelExists && (
                <Alert severity="warning" sx={{ mt: 1 }}>
                  A model with the name "{modelName}" is already loaded. Please choose a different name or unload the existing model first.
                </Alert>
              )}
              
              <Button
                variant="contained"
                onClick={handleLoadModel}
                disabled={processing || modelExists}
                startIcon={processing ? <CircularProgress size={20} /> : <Security />}
                sx={{ 
                  mt: 2,
                  backgroundColor: modelExists ? '#9E9E9E' : '#2196F3',
                  '&:hover': { backgroundColor: modelExists ? '#9E9E9E' : '#1976D2' }
                }}
                fullWidth
              >
                {processing ? 'Loading...' : modelExists ? 'Model Already Loaded' : 'Load Secure Model'}
              </Button>
              
              <Button
                variant="outlined"
                onClick={fetchLoadedModels}
                size="small"
                sx={{ mt: 1 }}
                fullWidth
              >
                Refresh Model List
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Progress Stepper */}
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
                  As a consumer you would receive access to the model weights via a control plane api functionality instead of a simple S3 bucket access demomstrated here.
                </Typography>
              </CardContent>
            </Card>
            
            {/* Processing Progress */}
            <Card sx={{ backgroundColor: '#E8F5E8', height: '600px', display: 'flex', flexDirection: 'column' }}>
            <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                Loading Progress
              </Typography>
              
              {/* Debug Toggle */}
              <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => updateState({ showDebug: !showDebug })}
                  startIcon={<BugReport />}
                >
                  Debug {showDebug ? 'ON' : 'OFF'}
                </Button>
              </Box>
              
              {/* Debug Info - only show when enabled */}
              {showDebug && (
                <Box sx={{ mb: 2, p: 1, backgroundColor: '#e0f0ff', fontSize: '0.7rem' }}>
                  Debug - All subSteps: {JSON.stringify(subSteps)}<br/>
                  Debug - Current Step: {currentStep}<br/>
                  Debug - Processing: {processing ? 'true' : 'false'}
                </Box>
              )}
              
              <Box 
                ref={progressScrollRef}
                sx={{ 
                  flex: 1, 
                  overflowY: 'auto', 
                  overflowX: 'hidden',
                  pr: 1,
                  '&::-webkit-scrollbar': {
                    width: '8px',
                  },
                  '&::-webkit-scrollbar-track': {
                    background: '#f1f1f1',
                    borderRadius: '4px',
                  },
                  '&::-webkit-scrollbar-thumb': {
                    background: '#c1c1c1',
                    borderRadius: '4px',
                  },
                  '&::-webkit-scrollbar-thumb:hover': {
                    background: '#a8a8a8',
                  },
                }}
              >
              {steps.map((step, index) => {
                const progress = stepProgress[index] || {};
                const isActive = currentStep === index;
                const isCompleted = progress.status === 'completed';
                const hasError = progress.status === 'error';
                const hasProgress = progress.progress !== undefined && !isCompleted;
                
                return (
                  <Box key={step.id} data-step={index} sx={{ mb: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <Box sx={{ mr: 2 }}>
                        {getStepIcon(index)}
                      </Box>
                      <Typography variant="h6" sx={{ 
                        color: isCompleted ? '#4CAF50' : hasError ? '#f44336' : '#4A4A4A'
                      }}>
                        {step.title}
                      </Typography>
                    </Box>
                    
                    {progress.message && (
                      <Typography variant="body2" color="textSecondary" sx={{ mb: 1, ml: 5 }}>
                        {progress.message}
                      </Typography>
                    )}
                    
                    {hasProgress && (
                      <Box sx={{ ml: 5, mr: 2 }}>
                        <LinearProgress 
                          variant="determinate" 
                          value={progress.progress} 
                          sx={{ height: 8, borderRadius: 4 }}
                        />
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
                          <Typography variant="caption" color="textSecondary">
                            {progress.progress?.toFixed(1)}%
                          </Typography>
                          {progress.downloaded && progress.total && (
                            <Typography variant="caption" color="textSecondary">
                              {formatBytes(progress.downloaded)} / {formatBytes(progress.total)}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                    )}
                    
                    {/* Sub-steps for any step that has them */}
                    {subSteps[index] && Object.keys(subSteps[index]).length > 0 && (
                      <Box sx={{ ml: 5, mt: 1, backgroundColor: '#f9f9f9', p: 1, borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ fontWeight: 'bold', color: '#666' }}>Sub-steps:</Typography>
                        {Object.entries(subSteps[index]).map(([subStepKey, subStep]) => (
                          <Box key={subStepKey} sx={{ mb: 1, mt: 0.5 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                              <Box sx={{ mr: 1 }}>
                                {subStep.status === 'completed' ? (
                                  <CheckCircle sx={{ color: '#4CAF50', fontSize: 16 }} />
                                ) : subStep.status === 'active' ? (
                                  <CircularProgress size={16} />
                                ) : (
                                  <ArrowForward sx={{ color: '#999', fontSize: 16 }} />
                                )}
                              </Box>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
                                <Typography variant="body2" sx={{ 
                                  color: subStep.status === 'completed' ? '#4CAF50' : subStep.status === 'active' ? '#4A4A4A' : '#999',
                                  fontSize: '0.85rem'
                                }}>
                                  {subStep.message}
                                </Typography>
                                {subStep.status === 'completed' && subStep.duration && (
                                  <Chip 
                                    label={`${(subStep.duration / 1000).toFixed(1)}s`}
                                    size="small"
                                    sx={{ 
                                      backgroundColor: '#E8F5E8', 
                                      color: '#4CAF50',
                                      fontSize: '0.7rem',
                                      height: '20px'
                                    }}
                                  />
                                )}
                              </Box>
                            </Box>
                            
                            {/* Progress bar for sub-steps with progress */}
                            {subStep.progress !== undefined && subStep.status === 'active' && (
                              <Box sx={{ ml: 3, mr: 2 }}>
                                <LinearProgress 
                                  variant="determinate" 
                                  value={subStep.progress} 
                                  sx={{ height: 6, borderRadius: 3 }}
                                />
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
                                  <Typography variant="caption" color="textSecondary" sx={{ fontSize: '0.7rem' }}>
                                    {subStep.progress?.toFixed(1)}%
                                  </Typography>
                                  {subStep.processed && subStep.total && (
                                    <Typography variant="caption" color="textSecondary" sx={{ fontSize: '0.7rem' }}>
                                      {formatBytes(subStep.processed)} / {formatBytes(subStep.total)}
                                    </Typography>
                                  )}
                                </Box>
                              </Box>
                            )}
                          </Box>
                        ))}
                      </Box>
                    )}
                    
                    {/* Debug: Show subSteps state - only when debug is enabled */}
                    {showDebug && subSteps[index] && (
                      <Box sx={{ ml: 5, mt: 1, p: 1, backgroundColor: '#f0f0f0', fontSize: '0.7rem' }}>
                        Debug - SubSteps[{index}]: {JSON.stringify(subSteps[index])}
                      </Box>
                    )}
                    

                    
                    {stepResults[index] && (
                      <Box sx={{ mt: 1, ml: 5 }}>
                        {stepResults[index].model_size && (
                          <Chip 
                            label={`Size: ${formatBytes(stepResults[index].model_size)}`}
                            size="small"
                            sx={{ backgroundColor: '#C8E6C9', mr: 1 }}
                          />
                        )}
                        {stepResults[index].model_name && (
                          <Chip 
                            label={`Model: ${stepResults[index].model_name}`}
                            size="small"
                            sx={{ backgroundColor: '#BBDEFB', mr: 1 }}
                          />
                        )}
                        {stepResults[index].model_hash && (
                          <Chip 
                            label={`Hash: ${stepResults[index].model_hash}`}
                            size="small"
                            sx={{ backgroundColor: '#FFE0B2' }}
                          />
                        )}
                      </Box>
                    )}
                    
                    {/* Show hash result for Calculate Model Hash step */}
                    {index === 2 && stepResults[2] && stepResults[2].model_hash && (
                      <Box sx={{ mt: 1, ml: 5 }}>
                        <Chip 
                          label={`SHA256: ${stepResults[2].model_hash}`}
                          size="small"
                          sx={{ backgroundColor: '#FFE0B2' }}
                        />
                      </Box>
                    )}
                    
                    {/* Show result for Load to Ollama step */}
                    {index === 3 && stepResults[3] && (
                      <Box sx={{ mt: 1, ml: 5 }}>
                        {stepResults[3].model_name && (
                          <Chip 
                            label={`Model: ${stepResults[3].model_name || modelName}`}
                            size="small"
                            sx={{ backgroundColor: '#BBDEFB', mr: 1 }}
                          />
                        )}
                        {stepResults[3].model_hash && (
                          <Chip 
                            label={`SHA256: ${stepResults[3].model_hash}`}
                            size="small"
                            sx={{ backgroundColor: '#FFE0B2' }}
                          />
                        )}
                      </Box>
                    )}
                    
                    {/* Show PCR extension result for Extend PCR15 step */}
                    {index === 4 && stepResults[4] && (
                      <Box sx={{ mt: 1, ml: 5 }}>
                        {stepResults[4].pcr_value && (
                          <Chip 
                            label={`PCR15: ${stepResults[4].pcr_value}`}
                            size="small"
                            sx={{ backgroundColor: '#E1BEE7' }}
                          />
                        )}
                        {stepResults[4].model_hash && (
                          <Chip 
                            label={`Hash: ${stepResults[4].model_hash}`}
                            size="small"
                            sx={{ backgroundColor: '#FFE0B2', ml: 1 }}
                          />
                        )}
                      </Box>
                    )}
                  </Box>
                );
              })}
              </Box>
              
              {/* Debug Messages Panel */}
              <Box sx={{ mt: 3 }}>
                <Button
                  startIcon={showDebug ? <ExpandLess /> : <ExpandMore />}
                  onClick={() => updateState({ showDebug: !showDebug })}
                  size="small"
                  sx={{ mb: 1 }}
                >
                  <BugReport sx={{ mr: 1 }} />
                  Debug Messages ({debugMessages.length})
                </Button>
                
                <Collapse in={showDebug}>
                  <Card sx={{ backgroundColor: '#f5f5f5', maxHeight: 200, overflow: 'auto' }}>
                    <CardContent sx={{ p: 1 }}>
                      <List dense>
                        {debugMessages.map((msg, index) => (
                          <ListItem key={index} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 30 }}>
                              <Typography variant="caption" color="textSecondary">
                                {msg.timestamp}
                              </Typography>
                            </ListItemIcon>
                            <ListItemText
                              primary={msg.message}
                              secondary={msg.type}
                              primaryTypographyProps={{ variant: 'body2', sx: { fontFamily: 'monospace' } }}
                              secondaryTypographyProps={{ variant: 'caption' }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Collapse>
              </Box>
            </CardContent>
            </Card>
          </Box>
        </Grid>
      </Grid>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => updateState({ error: null })}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => updateState({ success: false })}>
          Model "{modelName}" has been securely loaded and is ready for inference!
          {stepResults[1]?.model_hash && (
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                Hash: {stepResults[1]?.model_hash || stepResults[2]?.model_hash || stepResults[3]?.model_hash}
              </Typography>
            </Box>
          )}
        </Alert>
      )}
    </Box>
  );
}

export default ModelLoader;
