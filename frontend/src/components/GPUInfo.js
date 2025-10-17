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
  Button,
  LinearProgress
} from '@mui/material';
import {
  Memory as MemoryIcon,
  Refresh as RefreshIcon,
  DeviceHub as GPUIcon,
  Thermostat as TempIcon,
  ElectricBolt as PowerIcon
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function GPUInfo() {
  const [gpuData, setGpuData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchGPUData();
  }, []);

  const fetchGPUData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE_URL}/tee/gpu`);
      setGpuData(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch GPU information');
    } finally {
      setLoading(false);
    }
  };

  const formatMemory = (mb) => {
    if (!mb || mb === 'N/A') return 'N/A';
    const num = parseInt(mb);
    if (num >= 1024) {
      return `${(num / 1024).toFixed(1)} GB`;
    }
    return `${num} MB`;
  };

  const getUtilizationColor = (percent) => {
    if (!percent || percent === 'N/A') return 'default';
    const num = parseInt(percent);
    if (num < 30) return 'success';
    if (num < 70) return 'warning';
    return 'error';
  };

  const renderGPUCard = (gpu, index) => (
    <Card key={index} sx={{ backgroundColor: '#E8F5E8', mb: 2 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
          <GPUIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          GPU {gpu.gpu_id}: {gpu.name}
        </Typography>
        
        <Grid container spacing={2}>
          {/* Basic Info */}
          <Grid item xs={12} md={6}>
            <TableContainer component={Paper} sx={{ backgroundColor: '#F5F5F5' }}>
              <Table size="small">
                <TableBody>
                  <TableRow>
                    <TableCell><strong>Driver Version</strong></TableCell>
                    <TableCell>{gpu.driver_version}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell><strong>CUDA Version</strong></TableCell>
                    <TableCell>{gpu.cuda_version}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell><strong>PCI Bus ID</strong></TableCell>
                    <TableCell>{gpu.pci_bus_id}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell><strong>UUID</strong></TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                      {gpu.uuid}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>
          
          {/* Performance Metrics */}
          <Grid item xs={12} md={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                <MemoryIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Memory Usage
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Box sx={{ width: '100%', mr: 1 }}>
                  <LinearProgress
                    variant="determinate"
                    value={gpu.memory_total_mb ? (parseInt(gpu.memory_used_mb) / parseInt(gpu.memory_total_mb)) * 100 : 0}
                    sx={{ height: 8, borderRadius: 4 }}
                  />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ minWidth: 35 }}>
                  {gpu.memory_total_mb ? Math.round((parseInt(gpu.memory_used_mb) / parseInt(gpu.memory_total_mb)) * 100) : 0}%
                </Typography>
              </Box>
              <Typography variant="caption">
                {formatMemory(gpu.memory_used_mb)} / {formatMemory(gpu.memory_total_mb)} used
              </Typography>
            </Box>
            
            <Grid container spacing={1}>
              <Grid item xs={6}>
                <Box sx={{ textAlign: 'center', p: 1, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                  <TempIcon color="action" />
                  <Typography variant="h6">{gpu.temperature_c}°C</Typography>
                  <Typography variant="caption">Temperature</Typography>
                </Box>
              </Grid>
              <Grid item xs={6}>
                <Box sx={{ textAlign: 'center', p: 1, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                  <PowerIcon color="action" />
                  <Typography variant="h6">{gpu.power_draw_w}W</Typography>
                  <Typography variant="caption">Power Draw</Typography>
                </Box>
              </Grid>
            </Grid>
            
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Utilization</Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Chip
                  label={`GPU: ${gpu.utilization_gpu_percent}%`}
                  color={getUtilizationColor(gpu.utilization_gpu_percent)}
                  size="small"
                />
                <Chip
                  label={`Memory: ${gpu.utilization_memory_percent}%`}
                  color={getUtilizationColor(gpu.utilization_memory_percent)}
                  size="small"
                />
              </Box>
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );

  const renderSummary = () => {
    if (!gpuData || gpuData.status !== 'success') return null;

    return (
      <Card sx={{ backgroundColor: '#F3E5F5', mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
            <GPUIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            GPU Summary
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                <Typography variant="h4" color="primary">
                  {gpuData.gpu_count}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  GPU Count
                </Typography>
              </Box>
            </Grid>
            
            {gpuData.gpus && gpuData.gpus.length > 0 && (
              <>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                    <Typography variant="h6" color="primary">
                      {gpuData.gpus[0].driver_version}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      Driver Version
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                    <Typography variant="h6" color="primary">
                      {gpuData.gpus[0].cuda_version}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      CUDA Version
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ textAlign: 'center', p: 2, backgroundColor: '#FFFBF0', borderRadius: 1 }}>
                    <Typography variant="h6" color="primary">
                      {formatMemory(gpuData.gpus.reduce((total, gpu) => total + parseInt(gpu.memory_total_mb || 0), 0))}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      Total Memory
                    </Typography>
                  </Box>
                </Grid>
              </>
            )}
          </Grid>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ color: '#4A4A4A' }}>
          GPU Information
        </Typography>
        
        <Button
          variant="outlined"
          onClick={fetchGPUData}
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

      {gpuData && (
        <>
          {gpuData.status === 'error' ? (
            <Alert severity="warning" sx={{ mb: 3 }}>
              {gpuData.message}
            </Alert>
          ) : (
            <>
              {renderSummary()}
              {gpuData.gpus && gpuData.gpus.map((gpu, index) => renderGPUCard(gpu, index))}
            </>
          )}
        </>
      )}
    </Box>
  );
}

export default GPUInfo;