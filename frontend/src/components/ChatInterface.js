import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemText,
  Chip,
  CircularProgress,
  Tabs,
  Tab,
  IconButton,
} from '@mui/material';
import { Send as SendIcon, Add as AddIcon, Close as CloseIcon } from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || '';

function ChatInterface({ state, setState }) {
  const [models, setModels] = useState([]);
  const [selectedModel, setSelectedModel] = useState('');
  const [chatSessions, setChatSessions] = useState([{ id: 1, name: 'Chat 1', messages: [] }]);
  const [activeSession, setActiveSession] = useState(0);
  
  // Initialize from state on mount
  useEffect(() => {
    if (state?.selectedModel) setSelectedModel(state.selectedModel);
    if (state?.chatSessions) setChatSessions(state.chatSessions);
    if (state?.activeSession !== undefined) setActiveSession(state.activeSession);
  }, []);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetchModels();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [chatSessions, activeSession]);

  useEffect(() => {
    if (setState) {
      setState({
        selectedModel,
        chatSessions,
        activeSession
      });
    }
  }, [selectedModel, chatSessions, activeSession, setState]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const fetchModels = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/models?_t=${Date.now()}`);
      setModels(response.data.models);
      if (response.data.models.length > 0) {
        setSelectedModel(response.data.models[0].name);
      }
    } catch (error) {
      console.error('Error fetching models:', error);
    }
  };

  const addNewSession = () => {
    const newId = Math.max(...chatSessions.map(s => s.id)) + 1;
    setChatSessions(prev => [...prev, { id: newId, name: `Chat ${newId}`, messages: [] }]);
    setActiveSession(chatSessions.length);
  };

  const closeSession = (index) => {
    if (chatSessions.length === 1) return;
    setChatSessions(prev => prev.filter((_, i) => i !== index));
    if (activeSession >= index && activeSession > 0) {
      setActiveSession(activeSession - 1);
    }
  };

  const sendMessage = async () => {
    if (!inputMessage.trim() || !selectedModel || isStreaming) return;

    const userMessage = { role: 'user', content: inputMessage };
    const currentMessages = chatSessions[activeSession].messages;
    
    setChatSessions(prev => {
      const newSessions = [...prev];
      newSessions[activeSession].messages = [...currentMessages, userMessage];
      return newSessions;
    });
    
    setInputMessage('');
    setIsStreaming(true);

    const assistantMessage = { role: 'assistant', content: '' };
    setChatSessions(prev => {
      const newSessions = [...prev];
      newSessions[activeSession].messages = [...newSessions[activeSession].messages, assistantMessage];
      return newSessions;
    });

    try {
      const response = await fetch(`${API_BASE_URL}/chat/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        // nosemgrep: no-stringify-keys
        body: JSON.stringify({
          model: selectedModel,
          messages: [...currentMessages, userMessage],
        }),
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') continue;
            
            try {
              const parsed = JSON.parse(data);
              if (parsed.choices?.[0]?.delta?.content) {
                setChatSessions(prev => {
                  const newSessions = [...prev];
                  const messages = newSessions[activeSession].messages;
                  const lastMessage = messages[messages.length - 1];
                  if (lastMessage.role === 'assistant') {
                    lastMessage.content += parsed.choices[0].delta.content;
                  }
                  return newSessions;
                });
              }
            } catch (e) {
              console.error('Error parsing chunk:', e);
            }
          }
        }
      }
    } catch (error) {
      console.error('Error sending message:', error);
      setChatSessions(prev => {
        const newSessions = [...prev];
        const messages = newSessions[activeSession].messages;
        const lastMessage = messages[messages.length - 1];
        if (lastMessage.role === 'assistant') {
          lastMessage.content = 'Error: Failed to get response from the model.';
        }
        return newSessions;
      });
    } finally {
      setIsStreaming(false);
    }
  };

  const handleKeyPress = (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  };

  return (
    <Container maxWidth="md" sx={{ height: '80vh', display: 'flex', flexDirection: 'column', py: 2 }}>
      <Paper elevation={3} sx={{ p: 3, mb: 2, backgroundColor: '#E3F2FD' }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ color: '#4A4A4A', textAlign: 'center' }}>
          Ollama Chat Interface
        </Typography>
        
        <FormControl fullWidth sx={{ mt: 2 }}>
          <InputLabel>Select Model</InputLabel>
          <Select
            value={selectedModel}
            label="Select Model"
            onChange={(e) => setSelectedModel(e.target.value)}
            sx={{ backgroundColor: 'white' }}
          >
            {models.map((model) => (
              <MenuItem key={model.name} value={model.name}>
                <Box>
                  <Typography variant="body1">{model.name}</Typography>
                  <Typography variant="caption" color="textSecondary">
                    SHA256: {model.digest?.slice(0, 16)}...
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        
        <Box sx={{ mt: 2, display: 'flex', alignItems: 'center' }}>
          <Tabs 
            value={activeSession} 
            onChange={(e, newValue) => setActiveSession(newValue)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ flexGrow: 1 }}
          >
            {chatSessions.map((session, index) => (
              <Tab 
                key={session.id}
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {session.name}
                    {chatSessions.length > 1 && (
                      <IconButton 
                        size="small" 
                        onClick={(e) => {
                          e.stopPropagation();
                          closeSession(index);
                        }}
                        sx={{ ml: 1, p: 0.5 }}
                      >
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    )}
                  </Box>
                }
              />
            ))}
          </Tabs>
          <IconButton onClick={addNewSession} sx={{ ml: 1 }}>
            <AddIcon />
          </IconButton>
        </Box>
      </Paper>

      <Paper 
        elevation={2} 
        sx={{ 
          flex: 1, 
          display: 'flex', 
          flexDirection: 'column', 
          overflow: 'hidden',
          backgroundColor: '#F8F8F8'
        }}
      >
        <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
          <List>
            {(chatSessions[activeSession]?.messages || []).map((message, index) => (
              <ListItem key={index} sx={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                <Chip 
                  label={message.role === 'user' ? 'You' : 'Assistant'} 
                  color={message.role === 'user' ? 'primary' : 'secondary'}
                  size="small"
                  sx={{ mb: 1 }}
                />
                <Paper 
                  elevation={1} 
                  sx={{ 
                    p: 2, 
                    width: '100%',
                    backgroundColor: message.role === 'user' ? '#E8F5E8' : '#FFF3E0'
                  }}
                >
                  <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                    {message.content}
                  </Typography>
                </Paper>
              </ListItem>
            ))}
            {isStreaming && (
              <ListItem>
                <CircularProgress size={20} sx={{ color: '#2196F3' }} />
                <Typography variant="body2" sx={{ ml: 1, color: '#6A6A6A' }}>
                  Generating response...
                </Typography>
              </ListItem>
            )}
          </List>
          <div ref={messagesEndRef} />
        </Box>

        <Box sx={{ p: 2, borderTop: '1px solid #E0E0E0', backgroundColor: 'white' }}>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <TextField
              fullWidth
              multiline
              maxRows={4}
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Type your message..."
              variant="outlined"
              disabled={isStreaming || !selectedModel}
              sx={{ backgroundColor: 'white' }}
            />
            <Button
              variant="contained"
              onClick={sendMessage}
              disabled={!inputMessage.trim() || !selectedModel || isStreaming}
              sx={{ 
                minWidth: 'auto', 
                px: 2,
                backgroundColor: '#2196F3',
                '&:hover': {
                  backgroundColor: '#1976D2'
                }
              }}
            >
              <SendIcon />
            </Button>
          </Box>
        </Box>
      </Paper>
    </Container>
  );
}

export default ChatInterface;