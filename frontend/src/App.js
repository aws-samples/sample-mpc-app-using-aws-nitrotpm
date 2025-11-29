import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AppBar, Toolbar, Typography, Tabs, Tab, Box, IconButton, Popover } from '@mui/material';
import PaletteIcon from '@mui/icons-material/Palette';
import ChatInterface from './components/ChatInterface';
import AttestationViewer from './components/AttestationViewer';
import TEEEnvironment from './components/TEEEnvironment';
import GPUInfo from './components/GPUInfo';
import ModelLoader from './components/ModelLoader';
import KMSManager from './components/KMSManager';
import ModelOwnerManager from './components/ModelOwnerManager';
import PublishedModels from './components/PublishedModels';
import LoadedModels from './components/LoadedModels';
import AboutPage from './components/AboutPage';
import DebugTab from './components/DebugTab';
import { WebSocketProvider } from './contexts/WebSocketContext';

const createAppTheme = (backgroundColor) => createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#2196F3',
    },
    secondary: {
      main: '#64B5F6',
    },
    background: {
      default: backgroundColor,
      paper: '#FFFFFF',
    },
    text: {
      primary: '#4A4A4A',
      secondary: '#6A6A6A',
    },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: '#FAFAFA',
        },
      },
    },
  },
});

function TabPanel({ children, value, index }) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

function App() {
  const [primaryTab, setPrimaryTab] = useState(0);
  const [secondaryTab, setSecondaryTab] = useState(0);
  const [modelLoaderState, setModelLoaderState] = useState({});
  const [modelOwnerState, setModelOwnerState] = useState({});
  const [chatState, setChatState] = useState({ messages: [], selectedModel: '' });
  const [backgroundColor, setBackgroundColor] = useState('#E3F2FD');
  const [colorPickerAnchor, setColorPickerAnchor] = useState(null);

  const handlePrimaryTabChange = (event, newValue) => {
    setPrimaryTab(newValue);
    setSecondaryTab(0);
  };

  const handleSecondaryTabChange = (event, newValue) => {
    setSecondaryTab(newValue);
  };

  const handleColorPickerOpen = (event) => {
    setColorPickerAnchor(event.currentTarget);
  };

  const handleColorPickerClose = () => {
    setColorPickerAnchor(null);
  };

  const generateSpectrumColors = () => {
    const colors = [];
    // Generate spectrum colors with different hues and lightness
    for (let h = 0; h < 360; h += 30) {
      for (let l = 85; l >= 40; l -= 15) {
        colors.push(`hsl(${h}, 50%, ${l}%)`);
      }
    }
    return colors;
  };

  const spectrumColors = generateSpectrumColors();

  return (
    <WebSocketProvider>
      <ThemeProvider theme={createAppTheme(backgroundColor)}>
      <CssBaseline />
      <AppBar position="static" sx={{ backgroundColor: '#2196F3' }}>
        <Toolbar sx={{ flexDirection: 'column', alignItems: 'flex-start', py: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1, width: '100%', justifyContent: 'space-between' }}>
            <Typography variant="h5" component="div" sx={{ color: 'white', fontWeight: 'bold' }}>
              A Multi-party collaboration example for LLM vendors-consumers
            </Typography>
            <IconButton 
              onClick={handleColorPickerOpen}
              sx={{ color: 'white' }}
              title="Change Background Color"
            >
              <PaletteIcon />
            </IconButton>
          </Box>
          <Typography variant="subtitle1" component="div" sx={{ color: 'rgba(255,255,255,0.8)' }}>
            Using isolated compute environment enabled by EC2 Instance Attestation
          </Typography>
        </Toolbar>
      </AppBar>
      
      {/* Primary Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', backgroundColor: '#BBDEFB' }}>
        <Tabs 
          value={primaryTab} 
          onChange={handlePrimaryTabChange}
          sx={{ 
            '& .MuiTab-root': { color: '#4A4A4A', fontWeight: 'bold' },
            '& .Mui-selected': { color: '#1976D2 !important' },
            '& .MuiTabs-indicator': { backgroundColor: '#1976D2' }
          }}
        >
          <Tab label="About" />
          <Tab label="LLM Model Owner" />
          <Tab label="LLM Model Consumer" />
          <Tab label="EC2 Instance Attestation" />
          <Tab label="Environment" />
        </Tabs>
      </Box>
      
      {/* Secondary Tabs */}
      {primaryTab === 1 && (
        <Box sx={{ borderBottom: 1, borderColor: 'divider', backgroundColor: '#E3F2FD' }}>
          <Tabs 
            value={secondaryTab} 
            onChange={handleSecondaryTabChange}
            sx={{ 
              '& .MuiTab-root': { color: '#6A6A6A' },
              '& .Mui-selected': { color: '#2196F3 !important' },
              '& .MuiTabs-indicator': { backgroundColor: '#2196F3' }
            }}
          >
            <Tab label="Model Manager" />
            <Tab label="Seal Model weights" />
            <Tab label="Published Models" />
          </Tabs>
        </Box>
      )}
      
      {primaryTab === 2 && (
        <Box sx={{ borderBottom: 1, borderColor: 'divider', backgroundColor: '#E3F2FD' }}>
          <Tabs 
            value={secondaryTab} 
            onChange={handleSecondaryTabChange}
            sx={{ 
              '& .MuiTab-root': { color: '#6A6A6A' },
              '& .Mui-selected': { color: '#2196F3 !important' },
              '& .MuiTabs-indicator': { backgroundColor: '#2196F3' }
            }}
          >
            <Tab label="Loaded Models" />
            <Tab label="Model Loader" />
            <Tab label="Chat Interface" />
          </Tabs>
        </Box>
      )}
      
      {primaryTab === 4 && (
        <Box sx={{ borderBottom: 1, borderColor: 'divider', backgroundColor: '#E3F2FD' }}>
          <Tabs 
            value={secondaryTab} 
            onChange={handleSecondaryTabChange}
            sx={{ 
              '& .MuiTab-root': { color: '#6A6A6A' },
              '& .Mui-selected': { color: '#2196F3 !important' },
              '& .MuiTabs-indicator': { backgroundColor: '#2196F3' }
            }}
          >
            <Tab label="Instance Metadata" />
            <Tab label="GPU Information" />
            <Tab label="System Debug" />
          </Tabs>
        </Box>
      )}
      

      
      {/* Tab Panels */}
      <TabPanel value={primaryTab} index={0}>
        <AboutPage />
      </TabPanel>
      
      <TabPanel value={primaryTab} index={1}>
        {secondaryTab === 0 && <ModelOwnerManager state={modelOwnerState} setState={setModelOwnerState} />}
        {secondaryTab === 1 && <KMSManager />}
        {secondaryTab === 2 && <PublishedModels />}
      </TabPanel>
      
      <TabPanel value={primaryTab} index={2}>
        {secondaryTab === 0 && <LoadedModels />}
        {secondaryTab === 1 && <ModelLoader state={modelLoaderState} setState={setModelLoaderState} />}
        {secondaryTab === 2 && <ChatInterface state={chatState} setState={setChatState} />}
      </TabPanel>
      
      <TabPanel value={primaryTab} index={3}>
        <AttestationViewer />
      </TabPanel>
      
      <TabPanel value={primaryTab} index={4}>
        {secondaryTab === 0 && <TEEEnvironment />}
        {secondaryTab === 1 && <GPUInfo />}
        {secondaryTab === 2 && <DebugTab />}
      </TabPanel>
      
      <Popover
        open={Boolean(colorPickerAnchor)}
        anchorEl={colorPickerAnchor}
        onClose={handleColorPickerClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
      >
        <Box sx={{ p: 2, width: 400 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Background Color</Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 0.5, mb: 2 }}>
            {spectrumColors.map((color, index) => (
              <Box
                key={index}
                onClick={() => {
                  setBackgroundColor(color);
                  handleColorPickerClose();
                }}
                sx={{
                  width: 28,
                  height: 28,
                  backgroundColor: color,
                  border: backgroundColor === color ? '2px solid #2196F3' : '1px solid #ddd',
                  cursor: 'pointer',
                  '&:hover': {
                    transform: 'scale(1.1)',
                    zIndex: 1,
                  },
                }}
              />
            ))}
          </Box>
          <input
            type="color"
            onChange={(e) => {
              setBackgroundColor(e.target.value);
              handleColorPickerClose();
            }}
            style={{
              width: '100%',
              height: '40px',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          />
        </Box>
      </Popover>
      </ThemeProvider>
    </WebSocketProvider>
  );
}

export default App;