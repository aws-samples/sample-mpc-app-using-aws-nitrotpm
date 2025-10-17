import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip
} from '@mui/material';
import { 
  Refresh as RefreshIcon,
  Delete as DeleteIcon,
  Storage as StorageIcon,
  CloudDownload as CloudDownloadIcon
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function PublishedModels() {
  const [bucketContents, setBucketContents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [bucket, setBucket] = useState('');
  const [deleteDialog, setDeleteDialog] = useState({ open: false, key: '', name: '' });
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const savedBucket = sessionStorage.getItem('s3Bucket');
    if (savedBucket) {
      setBucket(savedBucket);
      fetchBucketContents(savedBucket);
    }
  }, []);

  const fetchBucketContents = async (bucketName = bucket) => {
    if (!bucketName) {
      setError('No S3 bucket configured. Please process a model first.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_BASE_URL}/s3/list/${bucketName}?_t=${Date.now()}`);
      setBucketContents(response.data.objects || []);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch bucket contents');
      setBucketContents([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await axios.delete(`${API_BASE_URL}/s3/delete/${bucket}/${deleteDialog.key}`);
      setDeleteDialog({ open: false, key: '', name: '' });
      fetchBucketContents();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete object');
    } finally {
      setDeleting(false);
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return 'N/A';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getFileType = (key) => {
    if (key.endsWith('.gguf')) return 'Model';
    if (key.includes('datakey')) return 'Data Key';
    if (key.includes('metadata')) return 'Metadata';
    return 'Other';
  };

  const getFileTypeColor = (type) => {
    switch (type) {
      case 'Model': return '#4CAF50';
      case 'Data Key': return '#FF9800';
      case 'Metadata': return '#2196F3';
      default: return '#9E9E9E';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ color: '#4A4A4A' }}>
          Published Models
        </Typography>
        <Button
          variant="contained"
          startIcon={loading ? <CircularProgress size={20} /> : <RefreshIcon />}
          onClick={() => fetchBucketContents()}
          disabled={loading || !bucket}
          sx={{ 
            backgroundColor: '#2196F3',
            '&:hover': { backgroundColor: '#1976D2' }
          }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </Button>
      </Box>

      {bucket && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <StorageIcon sx={{ mr: 1 }} />
            <Typography variant="body2">
              Bucket: <strong>{bucket}</strong>
            </Typography>
          </Box>
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card sx={{ backgroundColor: '#E3F2FD' }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ color: '#4A4A4A' }}>
            S3 Bucket Contents
          </Typography>
          
          {bucketContents.length === 0 && !loading ? (
            <Alert severity="info">
              No objects found in bucket. Process a model to see published content.
            </Alert>
          ) : (
            <TableContainer component={Paper} sx={{ backgroundColor: '#F8F9FA' }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ backgroundColor: '#E3F2FD' }}>
                    <TableCell><strong>Name</strong></TableCell>
                    <TableCell><strong>Type</strong></TableCell>
                    <TableCell><strong>Size</strong></TableCell>
                    <TableCell><strong>Last Modified</strong></TableCell>
                    <TableCell><strong>Actions</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {bucketContents.map((object, index) => (
                    <TableRow key={index} hover>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>
                        {object.key}
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={getFileType(object.key)}
                          size="small"
                          sx={{ 
                            backgroundColor: getFileTypeColor(getFileType(object.key)),
                            color: 'white',
                            fontWeight: 'bold'
                          }}
                        />
                      </TableCell>
                      <TableCell>{formatSize(object.size)}</TableCell>
                      <TableCell>{formatDate(object.last_modified)}</TableCell>
                      <TableCell>
                        <IconButton
                          color="error"
                          onClick={() => setDeleteDialog({ 
                            open: true, 
                            key: object.key, 
                            name: object.key.split('/').pop() 
                          })}
                          size="small"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog.open} onClose={() => setDeleteDialog({ open: false, key: '', name: '' })}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete <strong>{deleteDialog.name}</strong>?
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialog({ open: false, key: '', name: '' })}>
            Cancel
          </Button>
          <Button 
            onClick={handleDelete} 
            color="error" 
            variant="contained"
            disabled={deleting}
            startIcon={deleting ? <CircularProgress size={16} /> : <DeleteIcon />}
          >
            {deleting ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default PublishedModels;