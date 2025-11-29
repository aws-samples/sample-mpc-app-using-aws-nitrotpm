import React, { useState, useEffect } from 'react';
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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Paper,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction
} from '@mui/material';
import { 
  Key as KeyIcon,
  Security as SecurityIcon,
  Sync as SyncIcon,
  Save as SaveIcon,
  Add as AddIcon,
  Close as CloseIcon,
  Delete as DeleteIcon,
  Edit as EditIcon
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function KMSManager() {
  const [currentStep, setCurrentStep] = useState(1);
  const [kmsKeyId, setKmsKeyId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  const [currentPolicy, setCurrentPolicy] = useState(null);
  const [originalPolicy, setOriginalPolicy] = useState(null);
  const [pcrValues, setPcrValues] = useState({});
  
  const [policyStatements, setPolicyStatements] = useState([]);
  const [showStatementModal, setShowStatementModal] = useState(false);
  const [editingStatement, setEditingStatement] = useState(null);
  const [statementBuilder, setStatementBuilder] = useState({
    effect: 'Allow',
    actions: ['kms:Decrypt'],
    conditions: [],
    conditionLogic: 'AND',
    principalArn: ''
  });

  const kmsOperations = [
    { value: 'kms:Decrypt', label: 'Decrypt' },
    { value: 'kms:DeriveSharedSecret', label: 'DeriveSharedSecret' },
    { value: 'kms:GenerateDataKey', label: 'GenerateDataKey' },
    { value: 'kms:GenerateDataKeyPair', label: 'GenerateDataKeyPair' },
    { value: 'kms:GenerateRandom', label: 'GenerateRandom' }
  ];

  const conditionTypes = [
    { value: 'StringEquals', label: 'StringEquals' },
    { value: 'StringNotEquals', label: 'StringNotEquals' },
    { value: 'StringLike', label: 'StringLike' },
    { value: 'StringNotLike', label: 'StringNotLike' },
    { value: 'ForAllValues:StringEquals', label: 'ForAllValues:StringEquals' },
    { value: 'ForAllValues:StringNotEquals', label: 'ForAllValues:StringNotEquals' },
    { value: 'ForAllValues:StringLike', label: 'ForAllValues:StringLike' },
    { value: 'ForAllValues:StringNotLike', label: 'ForAllValues:StringNotLike' },
    { value: 'ForAnyValue:StringEquals', label: 'ForAnyValue:StringEquals' },
    { value: 'ForAnyValue:StringNotEquals', label: 'ForAnyValue:StringNotEquals' },
    { value: 'ForAnyValue:StringLike', label: 'ForAnyValue:StringLike' },
    { value: 'ForAnyValue:StringNotLike', label: 'ForAnyValue:StringNotLike' }
  ];

  useEffect(() => {
    fetchPCRValues();
    // Load KMS Key ID from session storage
    const savedKmsKey = sessionStorage.getItem('kmsKeyId');
    if (savedKmsKey) {
      setKmsKeyId(savedKmsKey);
    }
  }, []);

  const fetchPCRValues = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/attestation`);
      setPcrValues(response.data.attestation_document.pcrs);
    } catch (err) {
      console.error('Failed to fetch PCR values:', err);
    }
  };

  const createKMSKey = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_BASE_URL}/kms/create-key`);
      setKmsKeyId(response.data.key_id);
      sessionStorage.setItem('kmsKeyId', response.data.key_id);
      setSuccess('KMS key created successfully');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create KMS key');
    } finally {
      setLoading(false);
    }
  };

  const proceedToStep2 = async () => {
    if (!kmsKeyId) {
      setError('Please provide a KMS Key ID');
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE_URL}/kms/policy/${kmsKeyId}`);
      const policy = JSON.parse(response.data.policy);
      setCurrentPolicy(policy);
      setOriginalPolicy(JSON.parse(JSON.stringify(policy)));
      
      // Parse existing TPM attestation statements
      const tpmStatements = [];
      policy.Statement?.forEach((stmt, stmtIdx) => {
        if (stmt.Condition && Object.keys(stmt.Condition).some(condType => 
          Object.keys(stmt.Condition[condType]).some(key => key.includes('PCR'))
        )) {
          const conditions = [];
          Object.entries(stmt.Condition).forEach(([condType, condValue]) => {
            Object.entries(condValue).forEach(([key, value]) => {
              if (key.includes('PCR')) {
                conditions.push({
                  id: Date.now() + Math.random(),
                  type: condType,
                  key: key,
                  value: value
                });
              }
            });
          });
          
          tpmStatements.push({
            id: Date.now() + Math.random() + stmtIdx,
            sid: stmt.Sid,
            actions: Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action],
            conditions: conditions,
            conditionLogic: 'AND'
          });
        }
      });
      
      setPolicyStatements(tpmStatements);
      setCurrentStep(2);
      setSuccess('Policy loaded successfully');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load policy from KMS');
    } finally {
      setLoading(false);
    }
  };

  const openStatementModal = (statement = null) => {
    if (statement) {
      setEditingStatement(statement);
      setStatementBuilder({
        effect: statement.effect || 'Allow',
        actions: statement.actions,
        conditions: statement.conditions,
        conditionLogic: statement.conditionLogic,
        principalArn: statement.principalArn || ''
      });
    } else {
      setEditingStatement(null);
      setStatementBuilder({
        effect: 'Allow',
        actions: ['kms:Decrypt'],
        conditions: [],
        conditionLogic: 'AND',
        principalArn: ''
      });
    }
    setShowStatementModal(true);
  };

  const closeStatementModal = () => {
    setShowStatementModal(false);
    setEditingStatement(null);
  };

  const addConditionToStatement = () => {
    const newCondition = {
      id: Date.now(),
      type: 'StringEquals',
      key: 'kms:RecipientAttestation:NitroTPMPCR0',
      value: pcrValues['0'] || ''
    };
    
    setStatementBuilder(prev => ({
      ...prev,
      conditions: [...prev.conditions, newCondition]
    }));
  };

  const updateStatementCondition = (id, field, value) => {
    setStatementBuilder(prev => ({
      ...prev,
      conditions: prev.conditions.map(cond => 
        cond.id === id ? { ...cond, [field]: value } : cond
      )
    }));
  };

  const removeStatementCondition = (id) => {
    setStatementBuilder(prev => ({
      ...prev,
      conditions: prev.conditions.filter(cond => cond.id !== id)
    }));
  };

  const saveStatement = () => {
    if (statementBuilder.conditions.length === 0) {
      setError('Please add at least one PCR condition');
      return;
    }

    const newStatement = {
      id: editingStatement?.id || Date.now(),
      sid: `TPMAttestation${Date.now()}`,
      effect: statementBuilder.effect,
      actions: statementBuilder.actions,
      conditions: statementBuilder.conditions,
      conditionLogic: statementBuilder.conditionLogic,
      principalArn: statementBuilder.principalArn
    };

    if (editingStatement) {
      setPolicyStatements(prev => prev.map(stmt => 
        stmt.id === editingStatement.id ? newStatement : stmt
      ));
    } else {
      setPolicyStatements(prev => [...prev, newStatement]);
    }

    updatePolicyWithStatements(editingStatement ? 
      policyStatements.map(stmt => stmt.id === editingStatement.id ? newStatement : stmt) :
      [...policyStatements, newStatement]
    );

    closeStatementModal();
  };

  const deleteStatement = (id) => {
    const updatedStatements = policyStatements.filter(stmt => stmt.id !== id);
    setPolicyStatements(updatedStatements);
    updatePolicyWithStatements(updatedStatements);
  };

  const updatePolicyWithStatements = (statements) => {
    if (!currentPolicy) return;
    
    const updatedPolicy = JSON.parse(JSON.stringify(currentPolicy));
    
    // Remove existing TPM attestation statements
    updatedPolicy.Statement = updatedPolicy.Statement.filter(stmt => 
      !stmt.Sid || !stmt.Sid.includes('TPMAttestation')
    );
    
    // Add new TPM attestation statements
    statements.forEach(stmt => {
      const conditionObj = {};
      stmt.conditions.forEach(cond => {
        if (!conditionObj[cond.type]) conditionObj[cond.type] = {};
        conditionObj[cond.type][cond.key] = cond.value;
      });
      
      const tpmStatement = {
        Sid: stmt.sid,
        Effect: stmt.effect || 'Allow',
        Principal: {
          AWS: stmt.principalArn || `arn:aws:iam::${updatedPolicy.Statement[0]?.Principal?.AWS?.split(':')[4] || '*'}:root`
        },
        Action: stmt.actions,
        Resource: '*',
        Condition: conditionObj
      };
      
      updatedPolicy.Statement.push(tpmStatement);
    });
    
    setCurrentPolicy(updatedPolicy);
  };

  const updateKMSPolicy = async () => {
    if (!kmsKeyId || !currentPolicy) {
      setError('Please provide KMS Key ID and policy');
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      await axios.put(`${API_BASE_URL}/kms/policy/${kmsKeyId}`, {
        policy: JSON.stringify(currentPolicy, null, 2)
      });
      setOriginalPolicy(JSON.parse(JSON.stringify(currentPolicy)));
      setSuccess('KMS policy updated successfully');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update KMS policy');
    } finally {
      setLoading(false);
    }
  };

  const getPolicyDiff = () => {
    if (!originalPolicy || !currentPolicy) return JSON.stringify(currentPolicy, null, 2);
    
    const original = JSON.stringify(originalPolicy, null, 2);
    const current = JSON.stringify(currentPolicy, null, 2);
    
    if (original === current) return current;
    
    // Simple diff highlighting - in a real app, use a proper diff library
    return current;
  };

  const hasChanges = () => {
    if (!originalPolicy || !currentPolicy) return false;
    return JSON.stringify(originalPolicy) !== JSON.stringify(currentPolicy);
  };

  const renderStep1 = () => (
    <Card sx={{ backgroundColor: '#F3E5F5', maxWidth: 600, mx: 'auto' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
          <KeyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Step 1: KMS Key Configuration
        </Typography>
        
        <TextField
          fullWidth
          label="KMS Key ID"
          value={kmsKeyId}
          onChange={(e) => {
            setKmsKeyId(e.target.value);
            sessionStorage.setItem('kmsKeyId', e.target.value);
          }}
          margin="normal"
          placeholder="arn:aws:kms:us-east-1:123456789012:key/..."
          helperText={sessionStorage.getItem('kmsKeyId') ? 'Loaded from session' : 'Enter KMS Key ID or create new key'}
        />
        
        <Box sx={{ mt: 3, display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="outlined"
            onClick={createKMSKey}
            disabled={loading}
            startIcon={<AddIcon />}
          >
            Create New Key
          </Button>
          
          <Button
            variant="contained"
            onClick={proceedToStep2}
            disabled={loading || !kmsKeyId}
            sx={{ backgroundColor: '#1976D2', '&:hover': { backgroundColor: '#1565C0' } }}
          >
            Next
          </Button>
        </Box>
      </CardContent>
    </Card>
  );

  const renderStep2 = () => (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h6" sx={{ color: '#4A4A4A' }}>
            Step 2: Policy Configuration
          </Typography>
          <Typography variant="body2" color="textSecondary">
            KMS Key: {kmsKeyId}
          </Typography>
        </Box>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(1)}
          size="small"
        >
          Back
        </Button>
      </Box>
      
      <Grid container spacing={3}>
        {/* Statement Builder - Left */}
        <Grid item xs={12} md={6}>



          <Card sx={{ backgroundColor: '#FFF3E0' }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: '#4A4A4A' }}>
                  TPM Attestation Statements
                </Typography>
                
                <Button
                  variant="contained"
                  onClick={() => openStatementModal()}
                  startIcon={<AddIcon />}
                  sx={{ backgroundColor: '#FF9800', '&:hover': { backgroundColor: '#F57C00' } }}
                >
                  Add Statement
                </Button>
              </Box>
              
              {policyStatements.length === 0 ? (
                <Typography color="textSecondary" sx={{ textAlign: 'center', py: 4 }}>
                  No TPM attestation statements. Add one to get started.
                </Typography>
              ) : (
                <List>
                  {policyStatements.map((statement) => (
                    <ListItem key={statement.id} sx={{ mb: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                      <ListItemText
                        primary={
                          <Box>
                            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                              {statement.sid}
                            </Typography>
                            <Box sx={{ mt: 1 }}>
                              <Typography variant="body2" color="textSecondary">Actions:</Typography>
                              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                                {statement.actions.map((action) => (
                                  <Chip key={action} label={action} size="small" color="primary" />
                                ))}
                              </Box>
                            </Box>
                            <Box sx={{ mt: 1 }}>
                              <Typography variant="body2" color="textSecondary">
                                PCR Conditions:
                              </Typography>
                              {statement.conditions.map((condition, idx) => (
                                <Box key={condition.id} sx={{ mt: 0.5, pl: 2 }}>
                                  <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                                    {condition.type}: {condition.key} = {condition.value.substring(0, 20)}...
                                  </Typography>
                                </Box>
                              ))}
                            </Box>
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        <IconButton onClick={() => openStatementModal(statement)} size="small">
                          <EditIcon />
                        </IconButton>
                        <IconButton onClick={() => deleteStatement(statement.id)} size="small" color="error">
                          <DeleteIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Policy Viewer - Right */}
        <Grid item xs={12} md={6}>
          <Card sx={{ backgroundColor: '#E3F2FD' }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: '#4A4A4A' }}>
                  KMS Policy {hasChanges() && <Chip label="Modified" color="warning" size="small" />}
                </Typography>
                
                <Button
                  variant="contained"
                  onClick={updateKMSPolicy}
                  disabled={loading || !hasChanges()}
                  startIcon={<SaveIcon />}
                  sx={{ backgroundColor: '#1976D2', '&:hover': { backgroundColor: '#1565C0' } }}
                >
                  Update Policy
                </Button>
              </Box>
              
              <Paper sx={{ p: 2, backgroundColor: hasChanges() ? '#FFF9C4' : '#F5F5F5' }}>
                <pre style={{ 
                  margin: 0, 
                  fontFamily: 'monospace', 
                  fontSize: '0.8rem',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '500px',
                  overflow: 'auto'
                }}>
                  {getPolicyDiff()}
                </pre>
              </Paper>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: '#4A4A4A' }}>
        KMS Key Management
      </Typography>
      
      {currentStep === 1 ? renderStep1() : renderStep2()}

      {/* Status Messages */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      
      {success && (
        <Alert severity="success" sx={{ mt: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}
      
      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
          <CircularProgress />
        </Box>
      )}

      {/* Statement Builder Modal */}
      {currentStep === 2 && (
        <Dialog open={showStatementModal} onClose={closeStatementModal} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingStatement ? 'Edit Statement' : 'Add New Statement'}
          <IconButton
            onClick={closeStatementModal}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={6}>
              <TextField
                fullWidth
                label="Principal ARN"
                value={statementBuilder.principalArn}
                onChange={(e) => setStatementBuilder(prev => ({ ...prev, principalArn: e.target.value }))}
                placeholder="arn:aws:iam::123456789012:role/EC2-Instance-Role"
                helperText="Leave empty to use account root as principal"
              />
            </Grid>
            
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Effect</InputLabel>
                <Select
                  value={statementBuilder.effect}
                  onChange={(e) => setStatementBuilder(prev => ({ ...prev, effect: e.target.value }))}
                >
                  <MenuItem value="Allow">Allow</MenuItem>
                  <MenuItem value="Deny">Deny</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>KMS Actions</InputLabel>
                <Select
                  multiple
                  value={statementBuilder.actions}
                  onChange={(e) => setStatementBuilder(prev => ({ ...prev, actions: e.target.value }))}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={kmsOperations.find(op => op.value === value)?.label} size="small" />
                      ))}
                    </Box>
                  )}
                >
                  {kmsOperations.map((operation) => (
                    <MenuItem key={operation.value} value={operation.value}>
                      {operation.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h6">PCR Conditions</Typography>
                <Button
                  variant="outlined"
                  onClick={addConditionToStatement}
                  startIcon={<AddIcon />}
                  size="small"
                >
                  Add Condition
                </Button>
              </Box>
            </Grid>
            
            {statementBuilder.conditions.map((condition) => (
              <Grid item xs={12} key={condition.id}>
                <Card sx={{ p: 2, backgroundColor: '#F5F5F5' }}>
                  <Grid container spacing={2} alignItems="center">
                    <Grid item xs={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Type</InputLabel>
                        <Select
                          value={condition.type}
                          onChange={(e) => updateStatementCondition(condition.id, 'type', e.target.value)}
                        >
                          {conditionTypes.map((type) => (
                            <MenuItem key={type.value} value={type.value}>
                              {type.label}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Grid>
                    
                    <Grid item xs={3}>
                      <FormControl fullWidth size="small">
                        <InputLabel>PCR</InputLabel>
                        <Select
                          value={condition.key}
                          onChange={(e) => {
                            const pcrNumber = e.target.value.match(/PCR(\d+)/)?.[1];
                            const pcrValue = pcrValues[pcrNumber] || '';
                            updateStatementCondition(condition.id, 'key', e.target.value);
                            updateStatementCondition(condition.id, 'value', pcrValue);
                          }}
                        >
                          {Object.keys(pcrValues).map(pcr => (
                            <MenuItem key={pcr} value={`kms:RecipientAttestation:NitroTPMPCR${pcr}`}>
                              PCR{pcr}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Grid>
                    
                    <Grid item xs={5}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Expected Value"
                        value={condition.value}
                        InputProps={{ readOnly: true }}
                        sx={{ fontFamily: 'monospace' }}
                      />
                    </Grid>
                    
                    <Grid item xs={1}>
                      <IconButton
                        onClick={() => removeStatementCondition(condition.id)}
                        size="small"
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Grid>
                  </Grid>
                </Card>
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeStatementModal}>Cancel</Button>
          <Button onClick={saveStatement} variant="contained">
            {editingStatement ? 'Update' : 'Add'} Statement
          </Button>
        </DialogActions>
        </Dialog>
      )}
    </Box>
  );
}

export default KMSManager;