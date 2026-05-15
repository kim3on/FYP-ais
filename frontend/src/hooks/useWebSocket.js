import { useEffect, useRef, useCallback } from 'react';

const debugWebSocket = (...args) => {
  if (import.meta.env.DEV) {
    console.debug(...args);
  }
};

/**
 * useWebSocket — manages a WebSocket connection with auto-cleanup.
 *
 * @param {string}   url       WebSocket URL, e.g. '/ws/capture'
 * @param {function} onMessage Called with parsed JSON message
 * @param {boolean}  enabled   Connect only when true
 */
export function useWebSocket(url, onMessage, enabled = true) {
  const wsRef      = useRef(null);
  const onMsgRef   = useRef(onMessage);

  useEffect(() => {
    onMsgRef.current = onMessage; // always use latest callback without re-connecting
  }, [onMessage]);

  const connect = useCallback(() => {
    if (wsRef.current) return; // already connected

    // In dev Vite proxies /ws/* → ws://localhost:8000/ws/*
    // In prod same origin is used
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host     = window.location.host;
    
    // Add token for authentication (FastAPI /ws/live requires it in query string)
    const token = localStorage.getItem('ais_token');
    const separator = url.includes('?') ? '&' : '?';
    const urlWithToken = token ? `${url}${separator}token=${token}` : url;
    
    const fullUrl  = url.startsWith('ws') ? url : `${protocol}//${host}${urlWithToken}`;

    const ws = new WebSocket(fullUrl);

    ws.onopen    = () => debugWebSocket(`[WS] connected: ${url}`);
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        onMsgRef.current(data);
      } catch {
        onMsgRef.current(e.data); // pass raw if not JSON
      }
    };
    ws.onerror  = (e) => console.warn(`[WS] error on ${url}`, e);
    ws.onclose  = () => {
      debugWebSocket(`[WS] closed: ${url}`);
      wsRef.current = null;
    };

    wsRef.current = ws;
  }, [url]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      disconnect();
    }
    return () => disconnect(); // cleanup on unmount
  }, [enabled, connect, disconnect]);

  return { disconnect };
}
