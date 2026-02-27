export enum WebSocketState {
  CONNECTING = 'CONNECTING',
  CONNECTED = 'CONNECTED',
  DISCONNECTED = 'DISCONNECTED',
  RECONNECTING = 'RECONNECTING',
  FAILED = 'FAILED',
}

export interface PingMessage {
  type: 'ping';
  timestamp: number;
}

export interface JoinGroupMessage {
  type: 'join_group';
  data: { group_name: string };
}

export interface LeaveGroupMessage {
  type: 'leave_group';
  data: { group_name: string };
}

export type UserOutgoingMessage =
  | PingMessage
  | JoinGroupMessage
  | LeaveGroupMessage;

export interface PongEvent {
  type: 'pong';
  timestamp: number;
}

export interface ConnectedEvent {
  type: 'connected';
}

export interface ErrorEvent {
  type: 'error';
  message: string;
}

export type UserIncomingEvent =
  | PongEvent
  | ConnectedEvent
  | ErrorEvent;

export interface WebSocketConfig {
  url: string;
  urlProvider?: () => Promise<string | null>;
  reconnect?: boolean;
  reconnectInterval?: number;
  reconnectAttempts?: number;
  pingInterval?: number;
}
