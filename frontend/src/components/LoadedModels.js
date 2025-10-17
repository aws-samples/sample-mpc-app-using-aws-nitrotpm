import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Chip,
  Alert,
  CircularProgress,
  Divider
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import RefreshIcon from '@mui/icons-material/Refresh';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

const LoadedModels = () => {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(false);
  const [unloading, setUnloading] = useState({});
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchModels = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE_URL}/models/status?_t=${Date.now()}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setModels(data.models.models || []);
      } else {
        setError(data.message || 'Failed to fetch models');
      }
    } catch (err) {
      setError('Failed to connect to backend');
    } finally {
      setLoading(false);
    }
  };

  const unloadModel = async (modelName) => {
    setUnloading(prev => ({ ...prev, [modelName]: true }));
    setError('');
    setSuccess('');
    
    try {
      const response = await fetch(`${API_BASE_URL}/models/${encodeURIComponent(modelName)}`, {
        method: 'DELETE'
      });
      const data = await response.json();
      
      if (data.status === 'success') {
        setSuccess(`Model '${modelName}' unloaded successfully`);
        fetchModels(); // Refresh the list
      } else {
        setError(data.message || 'Failed to unload model');
      }
    } catch (err) {
      setError('Failed to unload model');
    } finally {
      setUnloading(prev => ({ ...prev, [modelName]: false }));
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return 'Unknown';
    const gb = bytes / (1024 * 1024 * 1024);
    return `${gb.toFixed(2)} GB`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleString();
  };

  useEffect(() => {
    fetchModels();
  }, []);

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6" component="h2">
            Loaded Models
          </Typography>
          <Button
            startIcon={<RefreshIcon />}
            onClick={fetchModels}
            disabled={loading}
            size="small"
          >
            Refresh
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
            {success}
          </Alert>
        )}

        {loading ? (
          <Box display="flex" justifyContent="center" p={2}>
            <CircularProgress />
          </Box>
        ) : models.length === 0 ? (
          <Typography color="textSecondary" align="center" py={2}>
            No models loaded
          </Typography>
        ) : (
          <List>
            {models.map((model, index) => (
              <React.Fragment key={model.name}>
                <ListItem>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Typography variant="subtitle1">
                          {model.name}
                        </Typography>
                        <Chip 
                          label={formatSize(model.size)} 
                          size="small" 
                          color="primary" 
                          variant="outlined"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="textSecondary">
                          Modified: {formatDate(model.modified_at)}
                        </Typography>
                        {model.digest && (
                          <Typography variant="body2" color="textSecondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                            SHA256: {model.digest}
                          </Typography>
                        )}
                        {model.details && (
                          <Box display="flex" gap={1} mt={0.5}>
                            {model.details.family && (
                              <Chip label={model.details.family} size="small" />
                            )}
                            {model.details.parameter_size && (
                              <Chip label={model.details.parameter_size} size="small" />
                            )}
                            {model.details.quantization_level && (
                              <Chip label={model.details.quantization_level} size="small" />
                            )}
                          </Box>
                        )}
                      </Box>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Button
                      startIcon={unloading[model.name] ? <CircularProgress size={16} /> : <DeleteIcon />}
                      onClick={() => unloadModel(model.name)}
                      disabled={unloading[model.name]}
                      color="error"
                      size="small"
                    >
                      {unloading[model.name] ? 'Unloading...' : 'Unload'}
                    </Button>
                  </ListItemSecondaryAction>
                </ListItem>
                {index < models.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        )}
      </CardContent>
    </Card>
  );
};

export default LoadedModels;