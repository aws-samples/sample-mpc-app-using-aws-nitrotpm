import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Alert,
  CircularProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableRow,
  Paper,
  Button
} from '@mui/material';
import {
  Cloud as CloudIcon,
  Security as SecurityIcon,
  Refresh as RefreshIcon,
  Computer as ComputerIcon
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function TEEEnvironment() {
  const [environmentData, setEnvironmentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchEnvironmentData();
  }, []);

  const fetchEnvironmentData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE_URL}/tee/environment`);
      setEnvironmentData(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch TEE environment data');
    } finally {
      setLoading(false);
    }
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) return 'N/A';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  };

  const renderInstanceIdentity = () => {
    if (!environmentData?.instance_identity) return null;

    const identity = environmentData.instance_identity;
    
    return (
      <Card sx={{ backgroundColor: '#E3F2FD', mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
            <ComputerIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Instance Identity
          </Typography>
          
          <TableContainer component={Paper} sx={{ backgroundColor: '#F5F5F5' }}>
            <Table size="small">
              <TableBody>
                {Object.entries(identity).map(([key, value]) => (
                  <TableRow key={key}>
                    <TableCell><strong>{key}</strong></TableCell>
                    <TableCell>
                      {key === 'instanceType' && value ? (
                        <Chip label={value} color="primary" size="small" />
                      ) : key === 'pendingTime' && value ? (
                        new Date(value).toLocaleString()
                      ) : (
                        formatValue(value)
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  const renderIAMInfo = () => {
    if (!environmentData?.iam_info) return null;

    const iam = environmentData.iam_info;
    
    return (
      <Card sx={{ backgroundColor: '#FFF3E0', mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            IAM Information
          </Typography>
          
          <TableContainer component={Paper} sx={{ backgroundColor: '#F5F5F5' }}>
            <Table size="small">
              <TableBody>
                <TableRow>
                  <TableCell><strong>Instance Profile ARN</strong></TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {iam.InstanceProfileArn}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell><strong>Instance Profile ID</strong></TableCell>
                  <TableCell>{iam.InstanceProfileId}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell><strong>Last Updated</strong></TableCell>
                  <TableCell>{new Date(iam.LastUpdated).toLocaleString()}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  const renderSummary = () => {
    if (!environmentData) return null;

    return (
      <Card sx={{ backgroundColor: '#F3E5F5', mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
            <CloudIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Environment Summary
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                <Typography variant="h4" color="primary">
                  {environmentData.account_id}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  AWS Account ID
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                <Typography variant="h6" color="primary">
                  {environmentData.region}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Region
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                <Typography variant="h6" color="primary">
                  {environmentData.instance_type}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Instance Type
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                <Typography variant="h6" color="primary">
                  {environmentData.architecture}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Architecture
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ color: '#4A4A4A' }}>
          Environment
        </Typography>
        
        <Button
          variant="outlined"
          onClick={fetchEnvironmentData}
          disabled={loading}
          startIcon={<RefreshIcon />}
        >
          Refresh
        </Button>
      </Box>

      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
          <CircularProgress />
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {environmentData && (
        <>
          {renderSummary()}
          {renderInstanceIdentity()}
          {renderIAMInfo()}
        </>
      )}
    </Box>
  );
}

export default TEEEnvironment;