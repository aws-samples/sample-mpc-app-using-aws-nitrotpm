import React, { createContext, useContext, useRef, useCallback } from 'react';

const WebSocketContext = createContext();

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

export const WebSocketProvider = ({ children }) => {
  const connectionsRef = useRef(new Map());
  const handlersRef = useRef(new Map());

  const connect = useCallback((clientId, url, handlers) => {
    // Close existing connection if any
    if (connectionsRef.current.has(clientId)) {
      const existingWs = connectionsRef.current.get(clientId);
      existingWs.close();
    }

    const ws = new WebSocket(url);
    connectionsRef.current.set(clientId, ws);
    handlersRef.current.set(clientId, handlers);

    ws.onopen = (event) => {
      console.log('WebSocket connected:', clientId);
      handlers.onOpen?.(event);
    };

    ws.onmessage = (event) => {
      const currentHandlers = handlersRef.current.get(clientId);
      currentHandlers?.onMessage?.(event);
    };

    ws.onerror = (event) => {
      console.error('WebSocket error:', clientId, event);
      const currentHandlers = handlersRef.current.get(clientId);
      currentHandlers?.onError?.(event);
    };

    ws.onclose = (event) => {
      console.log('WebSocket closed:', clientId, event.code, event.reason);
      const currentHandlers = handlersRef.current.get(clientId);
      connectionsRef.current.delete(clientId);
      handlersRef.current.delete(clientId);
      currentHandlers?.onClose?.(event);
    };

    return ws;
  }, []);

  const send = useCallback((clientId, data) => {
    const ws = connectionsRef.current.get(clientId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
      return true;
    }
    return false;
  }, []);

  const disconnect = useCallback((clientId) => {
    const ws = connectionsRef.current.get(clientId);
    if (ws) {
      ws.close();
      connectionsRef.current.delete(clientId);
      handlersRef.current.delete(clientId);
    }
  }, []);

  const getConnection = useCallback((clientId) => {
    return connectionsRef.current.get(clientId);
  }, []);

  const updateHandlers = useCallback((clientId, handlers) => {
    handlersRef.current.set(clientId, handlers);
  }, []);

  const value = {
    connect,
    send,
    disconnect,
    getConnection,
    updateHandlers
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};