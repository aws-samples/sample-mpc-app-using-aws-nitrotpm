import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  Button,
  CircularProgress,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
} from '@mui/material';
import { ExpandMore as ExpandMoreIcon, Refresh as RefreshIcon, VerifiedUser as VerifiedIcon } from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function AttestationViewer() {
  const [attestationDoc, setAttestationDoc] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tpmStatus, setTpmStatus] = useState(null);
  const [selectedCert, setSelectedCert] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [nonce, setNonce] = useState('');
  const [certificateChain, setCertificateChain] = useState([]);

  const fetchTpmStatus = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/tpm/status?_t=${Date.now()}`);
      setTpmStatus(response.data);
    } catch (err) {
      setTpmStatus({ tpm_available: false, device_path: '/dev/tpm0' });
    }
  };

  const fetchAttestationDoc = async () => {
    setLoading(true);
    setError(null);
    const newNonce = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
    setNonce(newNonce);
    try {
      const response = await axios.get(`${API_BASE_URL}/attestation?nonce=${encodeURIComponent(newNonce)}&_t=${Date.now()}`);
      console.log('Certificates received:', response.data.certificates);
      console.log('Certificate count:', response.data.certificates?.length);
      setAttestationDoc(response.data.attestation_document);
      setCertificateChain(response.data.certificates || []);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch attestation document');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTpmStatus();
    fetchAttestationDoc();
  }, []);

  const generateNonce = () => {
    const newNonce = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
    setNonce(newNonce);
  };

  const verifyAttestationDoc = async () => {
    setVerifying(true);
    setVerificationResult(null);
    try {
      const response = await axios.get(`${API_BASE_URL}/attestation?nonce=${encodeURIComponent(nonce)}&_t=${Date.now()}`);
      const doc = response.data.attestation_document;
      const certs = response.data.certificates || [];
      
      // Actual verification checks
      const nonceInDoc = doc.nonce ? atob(doc.nonce) : '';
      const nonceMatches = nonceInDoc === nonce;
      const hasValidCerts = certs.length >= 4; // Root, Regional, Zonal, Instance-TPM
      const rootVerified = response.data.root_verified === true;
      const attestationSignatureVerified = response.data.attestation_signature_verified === true;
      
      if (response.data.status === 'success' && response.data.certificate_chain_status === 'success') {
        setVerificationResult({
          status: nonceMatches && hasValidCerts && rootVerified && attestationSignatureVerified ? 'success' : 'warning',
          verification_results: {
            semantic_validation: response.data.status === 'success',
            certificate_chain_validation: response.data.certificate_chain_status === 'success',
            nonce_validation: nonceMatches,
            document_authenticity: attestationSignatureVerified,
            root_verified: rootVerified
          }
        });
        setAttestationDoc(doc);
        setCertificateChain(certs);
      } else {
        setVerificationResult({
          status: 'error',
          message: 'Certificate chain validation failed'
        });
      }
    } catch (err) {
      setVerificationResult({
        status: 'error',
        message: err.response?.data?.detail || 'Verification failed'
      });
    } finally {
      setVerifying(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const truncateString = (str, length = 32) => {
    if (!str) return 'N/A';
    return str.length > length ? `${str.substring(0, length)}...` : str;
  };

  const getCertByType = (certType) => {
    const typeMap = {
      'root': 'Root CA',
      'regional': 'Regional Certificate',
      'zonal': 'Zonal Certificate',
      'instance': 'Instance Certificate',
      'tpm': 'TPM Certificate'
    };
    return certificateChain.find(cert => cert.type === typeMap[certType]);
  };

  const pcrDescriptions = {
    '0': 'Core System Firmware Executable Code',
    '1': 'Core System Firmware Data',
    '2': 'Extended or pluggable executable code',
    '3': 'Extended or pluggable Firmware Data',
    '4': 'Boot Manager Code',
    '5': 'Boot Manager Code Configuration and Data and GPT Partition Table',
    '6': 'Host Platform Manufacturer Specifics',
    '7': 'Secure Boot Policy',
    '8': 'Bootloader (GRUB)',
    '9': 'Kernel and initrd',
    '10': 'IMA (Integrity Measurement Architecture)',
    '11': 'Unused',
    '12': 'Kernel command line override',
    '13': 'Unused',
    '14': 'Unused',
    '15': 'LLM Model Hash',
    '16': 'Debug/Development',
    '17': 'Dynamic Root of Trust for Measurement (DRTM)',
    '18': 'Trusted OS startup code',
    '19': 'Trusted OS configuration',
    '20': 'Trusted OS kernel/other code',
    '21': 'Firmware debugger',
    '22': 'Unused',
    '23': 'Application support'
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ color: '#4A4A4A' }}>
          NitroTPM Attestation Document
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Box sx={{ textAlign: 'right', mr: 2 }}>
            <Typography variant="caption" color="textSecondary">Input Nonce:</Typography>
            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {nonce}
            </Typography>
          </Box>
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={fetchAttestationDoc}
            disabled={loading || verifying}
            sx={{ 
              backgroundColor: '#2196F3',
              '&:hover': { backgroundColor: '#1976D2' }
            }}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
          
          <Button
            variant="outlined"
            startIcon={verifying ? <CircularProgress size={20} /> : <VerifiedIcon />}
            onClick={verifyAttestationDoc}
            disabled={loading || verifying || !attestationDoc}
            sx={{ 
              borderColor: '#4CAF50',
              color: '#4CAF50',
              '&:hover': { borderColor: '#388E3C', color: '#388E3C' }
            }}
          >
            {verifying ? 'Verifying...' : 'Verify'}
          </Button>
        </Box>
      </Box>

      {tpmStatus && (
        <Alert 
          severity={tpmStatus.tpm_available ? "success" : "warning"} 
          sx={{ mb: 3 }}
        >
          TPM Status: {tpmStatus.tpm_available ? "Available" : "Not Available"} 
          ({tpmStatus.device_path})
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}
      

      
      {/* Verification Results */}
      {verificationResult && (
        <Alert 
          severity={verificationResult.status === 'success' ? 'success' : verificationResult.status === 'warning' ? 'warning' : 'error'} 
          sx={{ mb: 3 }}
        >
          <Typography variant="h6" gutterBottom>
            Verification Results
          </Typography>
          {verificationResult.status === 'success' || verificationResult.status === 'warning' ? (
            <Box>
              <Typography variant="body2">
                {verificationResult.verification_results?.semantic_validation ? '✓' : '✗'} Semantic validation: {verificationResult.verification_results?.semantic_validation ? 'Passed' : 'Failed'}
              </Typography>
              <Typography variant="body2">
                {verificationResult.verification_results?.certificate_chain_validation ? '✓' : '✗'} Certificate chain validation: {verificationResult.verification_results?.certificate_chain_validation ? 'Passed' : 'Failed'}
              </Typography>
              <Typography variant="body2">
                {verificationResult.verification_results?.nonce_validation ? '✓' : '✗'} Nonce validation: {verificationResult.verification_results?.nonce_validation ? 'Passed' : 'Failed'}
              </Typography>
              <Typography variant="body2">
                {verificationResult.verification_results?.document_authenticity ? '✓' : '✗'} Document authenticity: {verificationResult.verification_results?.document_authenticity ? 'Verified' : 'Failed'}
              </Typography>
              <Typography variant="body2">
                {verificationResult.verification_results?.root_verified ? '✓' : '✗'} Root CA verification: {verificationResult.verification_results?.root_verified ? 'Passed' : 'Failed'}
              </Typography>
            </Box>
          ) : (
            <Typography variant="body2">{verificationResult.message}</Typography>
          )}
        </Alert>
      )}

      {attestationDoc && (
        <Grid container spacing={3}>
          {/* Nonce Card */}
          <Grid item xs={12} md={6}>
            <Card sx={{ backgroundColor: '#E8F5E8' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Nonce
                </Typography>
                <Paper 
                  sx={{ 
                    p: 2, 
                    backgroundColor: '#F0F8F0',
                    fontFamily: 'monospace',
                    fontSize: '0.9rem',
                    wordBreak: 'break-all'
                  }}
                >
                  {attestationDoc.nonce ? atob(attestationDoc.nonce) : 'No nonce in document'}
                </Paper>
              </CardContent>
            </Card>
          </Grid>
          
          {/* Module ID Card */}
          <Grid item xs={12} md={6}>
            <Card sx={{ backgroundColor: '#FFF3E0' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Module ID
                </Typography>
                <Paper 
                  sx={{ 
                    p: 2, 
                    backgroundColor: '#FFFBF0',
                    fontFamily: 'monospace',
                    fontSize: '0.9rem',
                    wordBreak: 'break-all'
                  }}
                >
                  {attestationDoc.module_id || 'No module ID provided'}
                </Paper>
              </CardContent>
            </Card>
          </Grid>
          
          {/* Timestamp Card */}
          <Grid item xs={12} md={3}>
            <Card sx={{ backgroundColor: '#F3E5F5', height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Timestamp
                </Typography>
                <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>
                  {formatTimestamp(attestationDoc.timestamp)}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          {/* Digest Algorithm Card */}
          <Grid item xs={12} md={3}>
            <Card sx={{ backgroundColor: '#E3F2FD', height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Digest Algorithm
                </Typography>
                <Chip 
                  label={attestationDoc.digest} 
                  color="primary" 
                  size="large"
                  sx={{ backgroundColor: '#BBDEFB', fontSize: '0.9rem', color: '#000000' }}
                />
              </CardContent>
            </Card>
          </Grid>
          
          {/* User Data Card */}
          <Grid item xs={12} md={3}>
            <Card sx={{ backgroundColor: '#FFEBEE', height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  User Data
                </Typography>
                <Paper 
                  sx={{ 
                    p: 2, 
                    backgroundColor: '#FFF5F5',
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    wordBreak: 'break-all',
                    maxHeight: 100,
                    overflow: 'auto'
                  }}
                >
                  {attestationDoc.user_data || 'No user data provided'}
                </Paper>
              </CardContent>
            </Card>
          </Grid>

          {/* Public Key Card */}
          <Grid item xs={12} md={3}>
            <Card sx={{ backgroundColor: '#E8F5E8', height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                  Public Key
                </Typography>
                <Paper 
                  sx={{ 
                    p: 2, 
                    backgroundColor: '#F0F8F0',
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    wordBreak: 'break-all',
                    maxHeight: 100,
                    overflow: 'auto'
                  }}
                >
                  {attestationDoc.public_key || 'No public key provided'}
                </Paper>
              </CardContent>
            </Card>
          </Grid>

          {/* PCR Values and Certificate Chain */}
          <Grid item xs={12}>
            <Grid container spacing={3}>
              {/* PCR Values */}
              <Grid item xs={12} lg={7}>
                <Card sx={{ backgroundColor: '#FFF3E0', height: selectedCert ? 'auto' : '400px' }}>
                  <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                    <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                      Platform Configuration Registers (PCRs)
                    </Typography>
                    <TableContainer 
                      component={Paper} 
                      sx={{ 
                        backgroundColor: '#FFFBF0',
                        flexGrow: 1,
                        maxHeight: selectedCert ? '500px' : '320px',
                        overflow: 'auto'
                      }}
                    >
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ backgroundColor: '#FFF3E0' }}><strong>PCR</strong></TableCell>
                            <TableCell sx={{ backgroundColor: '#FFF3E0' }}><strong>Description</strong></TableCell>
                            <TableCell sx={{ backgroundColor: '#FFF3E0' }}><strong>Value</strong></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {Object.entries(attestationDoc.pcrs || {}).map(([pcr, value]) => (
                            <TableRow key={pcr}>
                              <TableCell>
                                <Chip 
                                  label={`PCR ${pcr}`} 
                                  size="small"
                                  sx={{ backgroundColor: '#FFE0B2' }}
                                />
                              </TableCell>
                              <TableCell sx={{ fontSize: '0.85rem' }}>
                                {pcrDescriptions[pcr] || 'Unknown'}
                              </TableCell>
                              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>
                                {value}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </CardContent>
                </Card>
              </Grid>

              {/* Certificate Chain */}
              <Grid item xs={12} lg={5}>
                <Card sx={{ backgroundColor: '#F8BBD9', height: '100%' }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
                      Certificate Chain
                    </Typography>
                    
                    {/* Trust Chain Tree */}
                    <Box sx={{ p: 2, backgroundColor: '#F5F5F5', borderRadius: 1, mb: 2 }}>
                      <Typography variant="subtitle1" gutterBottom sx={{ color: '#4A4A4A' }}>
                        🔐 Trust Chain
                      </Typography>
                      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <Chip 
                          label="🏆 Root CA" 
                          onClick={() => setSelectedCert('root')}
                          size="small"
                          sx={{ 
                            mb: 1, 
                            backgroundColor: selectedCert === 'root' ? '#FF8A80' : '#FFCDD2',
                            cursor: 'pointer',
                            '&:hover': { backgroundColor: '#FF8A80' }
                          }} 
                        />
                        <Typography sx={{ color: '#666', fontSize: '0.8rem' }}>↓</Typography>
                        <Chip 
                          label="🏛️ Regional" 
                          onClick={() => setSelectedCert('regional')}
                          size="small"
                          sx={{ 
                            mb: 1, 
                            backgroundColor: selectedCert === 'regional' ? '#90CAF9' : '#BBDEFB',
                            cursor: 'pointer',
                            '&:hover': { backgroundColor: '#90CAF9' }
                          }} 
                        />
                        <Typography sx={{ color: '#666', fontSize: '0.8rem' }}>↓</Typography>
                        <Chip 
                          label="🌐 Zonal" 
                          onClick={() => setSelectedCert('zonal')}
                          size="small"
                          sx={{ 
                            mb: 1, 
                            backgroundColor: selectedCert === 'zonal' ? '#FFCC02' : '#FFE0B2',
                            cursor: 'pointer',
                            '&:hover': { backgroundColor: '#FFCC02' }
                          }} 
                        />
                        <Typography sx={{ color: '#666', fontSize: '0.8rem' }}>↓</Typography>
                        <Chip 
                          label="🔗 Instance" 
                          onClick={() => setSelectedCert('instance')}
                          size="small"
                          sx={{ 
                            mb: 1, 
                            backgroundColor: selectedCert === 'instance' ? '#A5D6A7' : '#C8E6C9',
                            cursor: 'pointer',
                            '&:hover': { backgroundColor: '#A5D6A7' }
                          }} 
                        />
                        <Typography sx={{ color: '#666', fontSize: '0.8rem' }}>↓</Typography>
                        <Chip 
                          label="🔐 TPM" 
                          onClick={() => setSelectedCert('tpm')}
                          size="small"
                          sx={{ 
                            backgroundColor: selectedCert === 'tpm' ? '#F48FB1' : '#F8BBD9',
                            cursor: 'pointer',
                            '&:hover': { backgroundColor: '#F48FB1' }
                          }} 
                        />
                      </Box>
                    </Box>

                    {/* Certificate Details */}
                    {selectedCert ? (
                      <Card sx={{ backgroundColor: '#FCF0F5' }}>
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom sx={{ color: '#4A4A4A' }}>
                            {getCertByType(selectedCert)?.type || 'Unknown'}
                          </Typography>
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="textSecondary">Subject</Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {getCertByType(selectedCert)?.subject || 'N/A'}
                            </Typography>
                          </Box>
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="textSecondary">Issuer</Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              {getCertByType(selectedCert)?.issuer || 'N/A'}
                            </Typography>
                          </Box>
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="textSecondary">Valid From</Typography>
                            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                              {getCertByType(selectedCert)?.valid_from || 'N/A'}
                            </Typography>
                          </Box>
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="textSecondary">Valid To</Typography>
                            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                              {getCertByType(selectedCert)?.valid_to || 'N/A'}
                            </Typography>
                          </Box>
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="textSecondary">Key Usage</Typography>
                            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                              {getCertByType(selectedCert)?.key_usage || 'N/A'}
                            </Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="textSecondary">Basic Constraints</Typography>
                            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                              {getCertByType(selectedCert)?.basic_constraints || 'N/A'}
                            </Typography>
                          </Box>
                        </CardContent>
                      </Card>
                    ) : (
                      <Card sx={{ backgroundColor: '#F5F5F5' }}>
                        <CardContent>
                          <Typography variant="body2" color="textSecondary" align="center">
                            Click a certificate to view details
                          </Typography>
                        </CardContent>
                      </Card>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Grid>


        </Grid>
      )}
    </Box>
  );
}

export default AttestationViewer;