import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Button,
  CircularProgress
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import RefreshIcon from '@mui/icons-material/Refresh';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

const DebugTab = () => {
  const [debugData, setDebugData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchDebugInfo = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/debug`);
      const data = await response.json();
      setDebugData(data);
    } catch (error) {
      console.error('Failed to fetch debug info:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDebugInfo();
  }, []);

  const getStatusColor = (status) => {
    if (status?.includes('active') || status?.includes('running')) return 'success';
    if (status?.includes('failed') || status?.includes('error')) return 'error';
    if (status?.includes('inactive') || status?.includes('stopped')) return 'warning';
    return 'default';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          System Debug Information
        </Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchDebugInfo}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      <Grid container spacing={3}>
        {/* System Info */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Information
              </Typography>
              {debugData?.system && (
                <Box>
                  <Typography variant="body2"><strong>Hostname:</strong> {debugData.system.hostname}</Typography>
                  <Typography variant="body2"><strong>Uptime:</strong> {debugData.system.uptime}</Typography>
                  <Typography variant="body2"><strong>Load Average:</strong> {debugData.system.loadavg}</Typography>
                  <Typography variant="body2"><strong>Memory:</strong> {debugData.system.memory}</Typography>
                  <Typography variant="body2"><strong>Disk Usage:</strong> {debugData.system.disk}</Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Network Info */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Network Configuration
              </Typography>
              {debugData?.network && (
                <Box>
                  <Typography variant="body2"><strong>Localhost Test:</strong> 
                    <Chip 
                      label={debugData.network.localhost_test ? 'PASS' : 'FAIL'} 
                      color={debugData.network.localhost_test ? 'success' : 'error'} 
                      size="small" 
                      sx={{ ml: 1 }}
                    />
                  </Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}><strong>Interfaces:</strong></Typography>
                  <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                    {debugData.network.interfaces}
                  </pre>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Service Status */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Service Status</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {debugData?.services && Object.entries(debugData.services).map(([service, info]) => (
                  <Grid item xs={12} md={6} key={service}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                          <Typography variant="subtitle1">{service}</Typography>
                          <Chip 
                            label={info.status} 
                            color={getStatusColor(info.status)} 
                            size="small"
                          />
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          {info.description}
                        </Typography>
                        {info.logs && (
                          <Box mt={1}>
                            <Typography variant="caption" display="block">Recent Logs:</Typography>
                            <pre style={{ fontSize: '10px', maxHeight: '100px', overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                              {info.logs}
                            </pre>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Process Information */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Running Processes</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap', maxHeight: '300px', overflow: 'auto' }}>
                {debugData?.processes}
              </pre>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Port Information */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Network Ports</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                {debugData?.ports}
              </pre>
            </AccordionDetails>
          </Accordion>
        </Grid>
      </Grid>
    </Box>
  );
};

export default DebugTab;