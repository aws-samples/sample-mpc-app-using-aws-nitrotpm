import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Paper,
  Avatar
} from '@mui/material';
import { 
  Person as PersonIcon,
  Business as BusinessIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  Chat as ChatIcon,
  VerifiedUser as VerifiedIcon
} from '@mui/icons-material';
import FlowDiagram from './FlowDiagram';

function AboutPage() {
  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: '#4A4A4A', textAlign: 'center', mb: 4 }}>
        A simple two party collaboration approach
      </Typography>
      
      <Paper sx={{ p: 3, mb: 4, backgroundColor: '#F8F9FA' }}>
        <Typography variant="body1" sx={{ fontSize: '1.1rem', lineHeight: 1.8, color: '#4A4A4A' }}>
          This sample app demonstrates how two (or more) parties that intend to collaborate on a LLM based app can do so by leveraging a isolate compute environment enabled by EC2 Instance attestation.
        </Typography>
      </Paper>
      
      <Grid container spacing={4}>
        {/* Party A - Model Owner */}
        <Grid item xs={12} md={6}>
          <Card sx={{ backgroundColor: '#E3F2FD', height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Avatar sx={{ backgroundColor: '#1976D2', mr: 2, width: 56, height: 56 }}>
                  <BusinessIcon sx={{ fontSize: 32 }} />
                </Avatar>
                <Typography variant="h5" sx={{ color: '#1976D2', fontWeight: 'bold' }}>
                  Party A - Model Owner
                </Typography>
              </Box>
              
              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.6 }}>
                Uses the Model owner part of the App, to envelop encrypt their intellectual property, the model weights, using AWS KMS and store them durably using Amazon S3 bucket, also helpful as a publishing mechanism for the other party.
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <VerifiedIcon sx={{ color: '#1976D2', mr: 1 }} />
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    Attestation Verification
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ ml: 4, color: '#666' }}>
                  Introspects the Attestable AMI recipe and uses verified Attestation document to seal model weights to desired measurements (PCR4, PCR7)
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <SecurityIcon sx={{ color: '#1976D2', mr: 1 }} />
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    Encryption & Storage
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ ml: 4, color: '#666' }}>
                  Encrypts model weights with AWS KMS and stores in S3
                </Typography>
              </Box>
              

            </CardContent>
          </Card>
        </Grid>
        
        {/* Party B - Model Consumer */}
        <Grid item xs={12} md={6}>
          <Card sx={{ backgroundColor: '#E8F5E8', height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Avatar sx={{ backgroundColor: '#388E3C', mr: 2, width: 56, height: 56 }}>
                  <PersonIcon sx={{ fontSize: 32 }} />
                </Avatar>
                <Typography variant="h5" sx={{ color: '#388E3C', fontWeight: 'bold' }}>
                  Party B - Model Consumer
                </Typography>
              </Box>
              
              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.6 }}>
                Uses the Model Loader and Chat interface parts of the App, similar to Party A, they introspects the application, packaging recipe and verify the attestation document before proceeding to trust the PCR measurements displayed.
              </Typography>
              
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <StorageIcon sx={{ color: '#388E3C', mr: 1 }} />
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    Model Loading
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ ml: 4, color: '#666' }}>
                  Securely loads encrypted models using NitroTPM attestation
                </Typography>
              </Box>
              
              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ChatIcon sx={{ color: '#388E3C', mr: 1 }} />
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    Attested Chat Interface
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ ml: 4, color: '#666' }}>
                  Verifies PCR4, PCR7, PCR12 and PCR15 (model weights) to ensure execution environment and specific model integrity
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        {/* Flow Diagram */}
        <Grid item xs={12}>
          <Card sx={{ backgroundColor: '#F5F5F5' }}>
            <CardContent>
              <FlowDiagram />
            </CardContent>
          </Card>
        </Grid>
        
        {/* Technical Architecture */}
        <Grid item xs={12}>
          <Card sx={{ backgroundColor: '#FFF3E0' }}>
            <CardContent>
              <Typography variant="h5" gutterBottom sx={{ color: '#F57C00', fontWeight: 'bold', textAlign: 'center' }}>
                EC2 Instance Attestation features
              </Typography>
              
              <Grid container spacing={3} sx={{ mt: 2 }}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Avatar sx={{ backgroundColor: '#FF9800', mx: 'auto', mb: 2, width: 64, height: 64 }}>
                      <SecurityIcon sx={{ fontSize: 36 }} />
                    </Avatar>
                    <Typography variant="h6" sx={{ color: '#F57C00', mb: 1 }}>
                      TPM Attestation
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#666' }}>
                      Hardware-backed attestation document with PCR measurements for execution environment verification
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Avatar sx={{ backgroundColor: '#FF9800', mx: 'auto', mb: 2, width: 64, height: 64 }}>
                      <StorageIcon sx={{ fontSize: 36 }} />
                    </Avatar>
                    <Typography variant="h6" sx={{ color: '#F57C00', mb: 1 }}>
                      Sealed sensitive data
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#666' }}>
                      Out of the box AWS KMS integration that facilitates envelope encrypting sensitive data that is conditionally sealed to the EC2 Instance attestation PCR(s)
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: 'center' }}>
                    <Avatar sx={{ backgroundColor: '#FF9800', mx: 'auto', mb: 2, width: 64, height: 64 }}>
                      <VerifiedIcon sx={{ fontSize: 36 }} />
                    </Avatar>
                    <Typography variant="h6" sx={{ color: '#F57C00', mb: 1 }}>
                      PCR Verification
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#666' }}>
                      Multi-layer verification including boot measurements (PCR4, PCR7) and model integrity (PCR15)
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default AboutPage;