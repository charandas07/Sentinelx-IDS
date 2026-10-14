/**
 * WebSocket hook for real-time SentinelX updates.
 */
import { useEffect, useRef, useCallback, useState } from 'react';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws';
const RECONNECT_DELAY = 3000;

export function useWebSocket({
  onStats,
  onAlert,
  onTraffic,
  onNotification,
  onDemoStarted,
  onDemoStage,
  onDemoStageResult,
  onDemoFinished,
} = {}) {
  const ws = useRef(null);
  const reconnectTimer = useRef(null);
  const pingInterval = useRef(null);
  const [connected, setConnected] = useState(false);
  const [reconnectCount, setReconnectCount] = useState(0);

  const onStatsRef = useRef(onStats);
  const onAlertRef = useRef(onAlert);
  const onTrafficRef = useRef(onTraffic);
  const onNotificationRef = useRef(onNotification);
  const onDemoStartedRef = useRef(onDemoStarted);
  const onDemoStageRef = useRef(onDemoStage);
  const onDemoStageResultRef = useRef(onDemoStageResult);
  const onDemoFinishedRef = useRef(onDemoFinished);

  useEffect(() => {
    onStatsRef.current = onStats;
    onAlertRef.current = onAlert;
    onTrafficRef.current = onTraffic;
    onNotificationRef.current = onNotification;
    onDemoStartedRef.current = onDemoStarted;
    onDemoStageRef.current = onDemoStage;
    onDemoStageResultRef.current = onDemoStageResult;
    onDemoFinishedRef.current = onDemoFinished;
  }, [onStats, onAlert, onTraffic, onNotification, onDemoStarted, onDemoStage, onDemoStageResult, onDemoFinished]);

  const connect = useCallback(() => {
    try {
      const token = localStorage.getItem('token');
      const wsUrl = token ? `${WS_URL}?token=${token}` : WS_URL;
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setConnected(true);
        setReconnectCount(0);
        // Send periodic pings
        pingInterval.current = setInterval(() => {
          if (ws.current?.readyState === WebSocket.OPEN) {
            ws.current.send('ping');
          }
        }, 20000);
      };

      ws.current.onclose = () => {
        setConnected(false);
        if (pingInterval.current) {
            clearInterval(pingInterval.current);
            pingInterval.current = null;
        }
        reconnectTimer.current = setTimeout(() => {
          setReconnectCount(c => {
            const next = c + 1;
            return next;
          });
        }, Math.min(1000 * Math.pow(2, reconnectCount), 30000));
      };

      ws.current.onerror = () => {
        ws.current?.close();
      };

      ws.current.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          switch (msg.type) {
            case 'stats':             onStatsRef.current?.(msg.data);              break;
            case 'alert':             onAlertRef.current?.(msg.data);              break;
            case 'traffic':           onTrafficRef.current?.(msg.data);            break;
            case 'notification':      onNotificationRef.current?.(msg.data);       break;
            case 'demo_started':      onDemoStartedRef.current?.(msg.data);        break;
            case 'demo_stage':        onDemoStageRef.current?.(msg.data);          break;
            case 'demo_stage_result': onDemoStageResultRef.current?.(msg.data);   break;
            case 'demo_finished':     onDemoFinishedRef.current?.(msg.data);       break;
          }
        } catch {}
      };
    } catch (e) {
        reconnectTimer.current = setTimeout(() => {
          setReconnectCount(c => c + 1);
        }, Math.min(1000 * Math.pow(2, reconnectCount), 30000));
    }
  }, [reconnectCount]);

  useEffect(() => {
    if (!connected && !reconnectTimer.current) {
        connect();
    }
  }, [connect, connected]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      if (pingInterval.current) {
          clearInterval(pingInterval.current);
      }
      ws.current?.close();
    };
  }, []);

  return { connected, reconnectCount };
}
