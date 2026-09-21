import { EventEmitter } from 'events';

export interface RealtimeEvent {
  channel: string;
  type: string;
  data: any;
  timestamp: string;
}

class RealtimeHub extends EventEmitter {
  public broadcast(channel: string, type: string, data: any) {
    const event: RealtimeEvent = {
      channel,
      type,
      data,
      timestamp: new Date().toISOString(),
    };
    this.emit(channel, event);
    this.emit('*', event);
  }
}

export const realtimeHub = new RealtimeHub();
